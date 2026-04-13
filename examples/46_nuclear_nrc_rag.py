"""
Nuclear Energy / NRC Compliance RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pre-filter for platforms
that process documents related to nuclear energy, reactor operations, radioactive
material handling, nuclear non-proliferation, and cross-border nuclear technology
transfer.  Four independent filter layers run sequentially; a document must pass
all four to be returned to the caller.

Commercial use cases:

  +------------------------------------------------------------------+-----------------------------------------------+
  | Platform / Product                                               | Applicable Regulation(s)                      |
  +------------------------------------------------------------------+-----------------------------------------------+
  | Nuclear power plant document management and operations          | NRC 10 CFR Part 50 operating licenses         |
  | Nuclear fuel cycle facility compliance systems                  | NRC 10 CFR Part 70 special nuclear material   |
  | Radioactive material transport management platforms             | NRC 10 CFR Part 71 package certification      |
  | Radiation worker health and safety compliance systems           | NRC 10 CFR Part 20 radiation protection       |
  | Nuclear occupational dose and ALARA program tracking           | 10 CFR §20.1101 ALARA; §20.1201 occ. dose    |
  | Nuclear classified information and clearance management         | AEA 42 U.S.C. §2162 Restricted Data          |
  | Safeguards information access control systems                   | NRC 10 CFR §73.21 safeguards information      |
  | Nuclear export licensing and non-proliferation compliance       | NRC 10 CFR Part 110 export/import licensing   |
  | IAEA safeguards verification and NPT compliance platforms       | NPT Article III; IAEA safeguards agreements   |
  | AI/ML-powered nuclear document retrieval and analysis           | 42 U.S.C. §2153 nuclear cooperation agreements|
  +------------------------------------------------------------------+-----------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — NRCLicensingFilter
      (NRC Licensing Requirements — 10 CFR Parts 50, 70, 71;
       administered by the U.S. Nuclear Regulatory Commission)
      Controls access to documents related to reactor operations, nuclear fuel
      cycle facilities, and radioactive material transportation, enforcing
      operating license requirements, special nuclear material licenses, and
      package certification standards.

      10 CFR Part 50 — Reactor Operating License: Power reactors and research
      reactors operating in the United States must hold a valid NRC operating
      license under 10 CFR Part 50 (Domestic Licensing of Production and
      Utilization Facilities).  Documents describing reactor operations for a
      facility without a valid Part 50 operating license are denied.

      10 CFR Part 70 — Special Nuclear Material License: Nuclear fuel cycle
      facilities that possess, use, or transfer special nuclear material
      (SNM) — including enriched uranium, plutonium, and uranium-233 — must
      hold a valid NRC license under 10 CFR Part 70 (Domestic Licensing of
      Special Nuclear Material).  Documents describing fuel cycle facility
      operations without a Part 70 SNM license are denied.

      10 CFR Part 71 — Radioactive Material Transport Certification: Packages
      used to transport radioactive material must be certified under 10 CFR
      Part 71 (Packaging and Transportation of Radioactive Material).
      Documents describing transport of radioactive material without a valid
      Part 71 package certification are denied.

      10 CFR Part 50 §50.21(c) — Research Reactor License Type: Research and
      test reactors operate under a non-power facility license issued under
      10 CFR §50.21(c).  Documents describing research reactor operations
      without confirmation of the appropriate §50.21(c) license type require
      human review to verify license classification.

  Layer 2 — NRCRadiationProtectionFilter
      (Radiation Protection Standards — 10 CFR Part 20;
       administered by the U.S. Nuclear Regulatory Commission)
      Controls access to documents that describe occupational and public
      radiation exposures, ALARA program documentation, and radioactive
      effluent discharges, enforcing dose limits and program requirements
      under the Standards for Protection Against Radiation.

      10 CFR §20.1201 Occupational Dose Limits: The annual occupational dose
      limit for radiation workers is 5 rem (50 mSv) total effective dose
      equivalent.  Documents describing occupational dose exposures in excess
      of 5 rem per year are denied as reflecting an unlicensed or exceedance
      condition requiring corrective action.

      10 CFR §20.1301 Public Dose Limits: The annual dose limit to members of
      the public from licensed nuclear activities is 100 millirem (1 mSv).
      Documents describing public dose exposures in excess of 100 mrem per
      year are denied.

      10 CFR §20.1101 ALARA Program: Licensees must maintain radiation
      exposures As Low As Reasonably Achievable (ALARA) through an
      established radiation protection program.  Documents for facilities
      without documented ALARA programs are denied.

      10 CFR Part 20 Appendix B — Effluent Concentrations: Radioactive
      effluent discharged to unrestricted areas must not exceed the
      concentration values in Appendix B to 10 CFR Part 20.  Documents
      describing effluent discharges where compliance with Appendix B is
      not confirmed require human review.

  Layer 3 — NDAClassifiedFilter
      (Atomic Energy Act Classified Information — 42 U.S.C. §2162;
       10 CFR §73.21 Safeguards Information; SUNSI controls;
       administered by the U.S. Department of Energy and NRC)
      Controls access to documents containing Restricted Data, Formerly
      Restricted Data, NRC Safeguards Information, and Sensitive Unclassified
      Nuclear Information, enforcing clearance-based access controls and
      need-to-know requirements.

      42 U.S.C. §2162 Restricted Data (RD): Restricted Data under the Atomic
      Energy Act includes all data concerning the design, production, or use
      of nuclear weapons.  Access to RD requires a DOE Q clearance.
      Documents containing Restricted Data without Q clearance authorization
      are denied.

      Formerly Restricted Data (FRD): Formerly Restricted Data has been
      jointly determined by DOE and DoD to have primary relevance to military
      applications and has been transferred to the DoD classification system.
      Access to FRD requires at minimum an L clearance.  Documents containing
      FRD without L clearance are denied.

      10 CFR §73.21 Safeguards Information: Safeguards information — including
      physical protection plans, security measures, and vulnerability
      assessments for nuclear facilities and materials — may only be disclosed
      to persons with authorized access under 10 CFR §73.21.  Documents
      containing safeguards information without authorized access are denied.

      Sensitive Unclassified Nuclear Information (SUNSI): SUNSI encompasses
      unclassified information that, if disclosed, could compromise the
      security of nuclear facilities or materials.  Documents containing SUNSI
      without verified need-to-know require human review.

  Layer 4 — NuclearCrossBorderFilter
      (Nuclear Non-Proliferation and Export Controls — 10 CFR Part 110;
       NPT Article III; 42 U.S.C. §2153 Nuclear Cooperation;
       administered by the NRC, DOE, and U.S. Department of State)
      Controls access to documents involving nuclear technology exports,
      fissile material transfers, nuclear cooperation with restricted
      countries, and dual-use nuclear item transfers to sensitive nations,
      enforcing non-proliferation commitments and export licensing requirements.

      10 CFR Part 110 — Nuclear Export License: The export of nuclear
      material, equipment, and technology from the United States requires a
      license from the NRC under 10 CFR Part 110 (Export and Import of Nuclear
      Equipment and Material).  Documents describing nuclear technology exports
      to non-NPT member states without a Part 110 export license are denied.

      NPT Article III — IAEA Safeguards: The Treaty on the Non-Proliferation
      of Nuclear Weapons (NPT) Article III requires that non-nuclear-weapon
      states accept IAEA safeguards on all nuclear activities.  Fissile
      material transfers without verification of an applicable IAEA safeguards
      agreement are denied.

      42 U.S.C. §2153 — Nuclear Cooperation Agreements (123 Agreements):
      The Atomic Energy Act §123 requires a bilateral nuclear cooperation
      agreement (123 Agreement) before significant nuclear transfers may be
      made to a foreign country.  Documents describing nuclear cooperation
      with CN/RU/KP/IR — countries without current U.S. 123 Agreements in
      good standing — are denied.

      NRC-Listed Sensitive Countries — Dual-Use Nuclear Items: The NRC and
      DOE maintain lists of sensitive countries for which dual-use nuclear
      items (items with both civilian and weapons applications) require
      enhanced review.  Documents describing dual-use nuclear item transfers
      to NRC-sensitive countries without DOE/NRC review are escalated to
      REQUIRES_HUMAN_REVIEW.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Partial list of NPT Non-Proliferation Treaty member states (nation codes).
#: Nuclear technology exports to states outside this set without a 10 CFR
#: Part 110 export license are denied.
NPT_MEMBER_STATES: frozenset[str] = frozenset(
    {"US", "UK", "FR", "DE", "JP", "AU", "CA", "IN", "PK", "ZA", "BR", "MX", "KR", "AR"}
)

#: Countries subject to blanket restriction on nuclear cooperation under
#: 42 U.S.C. §2153 (no current U.S. 123 Agreement in good standing).
RESTRICTED_NUCLEAR_COUNTRIES: frozenset[str] = frozenset({"CN", "RU", "KP", "IR"})

#: NRC/DOE-listed sensitive countries for which dual-use nuclear item transfers
#: require enhanced DOE/NRC review before export.
NRC_SENSITIVE_COUNTRIES: frozenset[str] = frozenset({"CN", "RU", "KP", "IR", "SY", "CU", "SD", "MM"})


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document.

    Fields
    ------
    decision     : "PERMITTED", "DENIED", "REQUIRES_HUMAN_REVIEW"
    regulation   : Short citation string (e.g. "10 CFR Part 50")
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
# Layer 1 — NRCLicensingFilter
#            NRC Operating License Requirements (10 CFR Parts 50, 70, 71)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NRCLicensingFilter:
    """Enforces NRC licensing requirements for nuclear facilities and transport.

    10 CFR Part 50: Power reactor without valid NRC operating license → DENIED.

    10 CFR Part 70: Nuclear fuel cycle facility without SNM license → DENIED.

    10 CFR Part 71: Radioactive material transport without package
    certification → DENIED.

    10 CFR §50.21(c): Research reactor without confirmed §50.21(c) license
    type → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "NRCLicensingFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate NRC licensing requirements for *doc*.

        Evaluation order
        ----------------
        1. Power reactor without nrc_part50_license → DENIED
           (10 CFR Part 50 operating license).
        2. Fuel cycle facility without nrc_part70_license → DENIED
           (10 CFR Part 70 special nuclear material license).
        3. Radioactive material transport without nrc_part71_cert → DENIED
           (10 CFR Part 71 package certification).
        4. Research reactor without §50.21(c) license type confirmed →
           REQUIRES_HUMAN_REVIEW (10 CFR §50.21(c)).
        5. Otherwise → PERMITTED.
        """
        facility_type = doc.get("facility_type", "")
        is_fuel_cycle_facility = facility_type == "fuel_cycle_facility"
        is_radioactive_transport = doc.get("is_radioactive_material_transport", False)
        is_research_reactor = facility_type == "research_reactor"
        is_power_reactor = facility_type == "power_reactor"

        # 10 CFR Part 50 — Power Reactor Operating License
        if is_power_reactor and not doc.get("nrc_part50_license", False):
            return FilterResult(
                decision="DENIED",
                regulation="10 CFR Part 50",
                reason=(
                    "NRC 10 CFR Part 50: Power reactor operations described without a valid NRC "
                    "operating license under 10 CFR Part 50 (Domestic Licensing of Production "
                    "and Utilization Facilities). All commercial power reactors must hold a "
                    "current NRC operating license authorizing fuel loading, reactor criticality, "
                    "and commercial power generation. Operating without a valid license "
                    "constitutes a violation of the Atomic Energy Act."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 10 CFR Part 70 — Special Nuclear Material License
        if is_fuel_cycle_facility and not doc.get("nrc_part70_license", False):
            return FilterResult(
                decision="DENIED",
                regulation="10 CFR Part 70",
                reason=(
                    "NRC 10 CFR Part 70: Nuclear fuel cycle facility operations described without "
                    "a valid NRC license under 10 CFR Part 70 (Domestic Licensing of Special "
                    "Nuclear Material). Facilities that possess, use, or transfer special nuclear "
                    "material — including enriched uranium, plutonium, and uranium-233 — must "
                    "hold a current NRC Part 70 license. Unlicensed possession of SNM "
                    "constitutes a violation of the Atomic Energy Act."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 10 CFR Part 71 — Radioactive Material Transport Package Certification
        if is_radioactive_transport and not doc.get("nrc_part71_cert", False):
            return FilterResult(
                decision="DENIED",
                regulation="10 CFR Part 71",
                reason=(
                    "NRC 10 CFR Part 71: Radioactive material transport described without a valid "
                    "NRC package certification under 10 CFR Part 71 (Packaging and Transportation "
                    "of Radioactive Material). All packages used to transport radioactive material "
                    "must be certified to meet NRC structural, thermal, radiation shielding, and "
                    "criticality safety standards. Uncertified transport is prohibited."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 10 CFR §50.21(c) — Research Reactor License Type
        if is_research_reactor and not doc.get("nrc_part50_license", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="10 CFR §50.21(c)",
                reason=(
                    "NRC 10 CFR §50.21(c): Research reactor operations described without "
                    "confirmed NRC non-power facility license under §50.21(c). Research and "
                    "test reactors operate under a different license type than commercial power "
                    "reactors; the appropriate license classification must be verified before "
                    "document access is granted to confirm regulatory compliance."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="10 CFR Parts 50, 70, 71",
            reason=(
                "Document satisfies NRC licensing requirements under 10 CFR Parts 50, 70, "
                "and 71 for nuclear facility operations and radioactive material transport."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 2 — NRCRadiationProtectionFilter
#            Radiation Protection Standards (10 CFR Part 20)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NRCRadiationProtectionFilter:
    """Enforces NRC radiation protection requirements under 10 CFR Part 20.

    10 CFR §20.1201 Occupational Dose: Dose exceeding 5 rem/year → DENIED.

    10 CFR §20.1301 Public Dose: Dose exceeding 100 mrem/year → DENIED.

    10 CFR §20.1101 ALARA: ALARA program not documented → DENIED.

    10 CFR Part 20 Appendix B: Effluent within Appendix B not confirmed →
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "NRCRadiationProtectionFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate NRC radiation protection requirements for *doc*.

        Evaluation order
        ----------------
        1. Occupational dose > 5 rem/year → DENIED
           (10 CFR §20.1201 annual limit).
        2. Public dose > 100 mrem/year → DENIED
           (10 CFR §20.1301 public dose limit).
        3. ALARA program not documented → DENIED
           (10 CFR §20.1101 ALARA requirement).
        4. Effluent discharge Appendix B compliance not confirmed →
           REQUIRES_HUMAN_REVIEW (10 CFR Part 20 Appendix B).
        5. Otherwise → PERMITTED.
        """
        occupational_dose = doc.get("occupational_dose_rem", 0)
        public_dose_mrem = doc.get("public_dose_mrem", 0)
        alara_documented = doc.get("alara_documented", True)
        effluent_within_appendix_b = doc.get("effluent_within_appendix_b", None)

        # 10 CFR §20.1201 — Occupational Dose Limit
        if occupational_dose > 5:
            return FilterResult(
                decision="DENIED",
                regulation="10 CFR §20.1201",
                reason=(
                    f"NRC 10 CFR §20.1201: Occupational radiation dose of {occupational_dose} rem "
                    f"exceeds the annual limit of 5 rem (50 mSv) total effective dose equivalent "
                    f"for radiation workers. Documents describing dose conditions that exceed the "
                    f"§20.1201 annual limit reflect a potential overexposure condition requiring "
                    f"immediate NRC notification and corrective action per 10 CFR §20.2203."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 10 CFR §20.1301 — Public Dose Limit
        if public_dose_mrem > 100:
            return FilterResult(
                decision="DENIED",
                regulation="10 CFR §20.1301",
                reason=(
                    f"NRC 10 CFR §20.1301: Public radiation dose of {public_dose_mrem} mrem "
                    f"exceeds the annual public dose limit of 100 millirem (1 mSv) from all "
                    f"licensed nuclear activities. Documents describing public dose conditions "
                    f"that exceed the §20.1301 annual limit indicate a regulatory exceedance "
                    f"requiring NRC notification and corrective action."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 10 CFR §20.1101 — ALARA Program
        if not alara_documented:
            return FilterResult(
                decision="DENIED",
                regulation="10 CFR §20.1101",
                reason=(
                    "NRC 10 CFR §20.1101: Radiation protection program without documented ALARA "
                    "(As Low As Reasonably Achievable) controls. All NRC licensees must maintain "
                    "an ALARA program as part of their radiation protection program under "
                    "§20.1101, including procedures for keeping occupational and public doses "
                    "as low as reasonably achievable. Absence of ALARA documentation indicates "
                    "a program deficiency."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 10 CFR Part 20 Appendix B — Effluent Concentrations
        if effluent_within_appendix_b is False:
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="10 CFR Part 20 Appendix B",
                reason=(
                    "NRC 10 CFR Part 20 Appendix B: Radioactive effluent discharge compliance "
                    "with Appendix B concentration limits has not been confirmed. Appendix B to "
                    "10 CFR Part 20 specifies the maximum concentrations of radionuclides "
                    "permitted in effluent released to unrestricted areas. The effluent data "
                    "requires review by qualified health physics personnel to verify compliance."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="10 CFR Part 20",
            reason=(
                "Document satisfies NRC radiation protection requirements under 10 CFR Part 20, "
                "including occupational and public dose limits, ALARA program requirements, "
                "and effluent concentration standards."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 3 — NDAClassifiedFilter
#            Nuclear Non-Disclosure / Classified Nuclear Information Controls
#            (42 U.S.C. §2162 Restricted Data; 10 CFR §73.21 Safeguards Info)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NDAClassifiedFilter:
    """Enforces nuclear classification and safeguards information controls.

    42 U.S.C. §2162 Restricted Data (RD): RD without Q clearance → DENIED.

    Formerly Restricted Data (FRD): FRD without L clearance → DENIED.

    10 CFR §73.21 Safeguards Information: Safeguards info without authorized
    access → DENIED.

    SUNSI: Sensitive unclassified nuclear info without need-to-know verified
    → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "NDAClassifiedFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate nuclear classification and safeguards access controls for *doc*.

        Evaluation order
        ----------------
        1. Classification == "RD" without q_clearance → DENIED
           (42 U.S.C. §2162 Restricted Data).
        2. Classification == "FRD" without l_clearance → DENIED
           (Formerly Restricted Data / DoD classification).
        3. safeguards_info without nrc_authorized_access → DENIED
           (10 CFR §73.21 Safeguards Information).
        4. sunsi_data without need_to_know_verified → REQUIRES_HUMAN_REVIEW
           (SUNSI controls).
        5. Otherwise → PERMITTED.
        """
        classification = doc.get("classification", "")
        safeguards_info = doc.get("safeguards_info", False)
        sunsi_data = doc.get("sunsi_data", False)

        # 42 U.S.C. §2162 — Restricted Data (RD)
        if classification == "RD" and not doc.get("q_clearance", False):
            return FilterResult(
                decision="DENIED",
                regulation="42 U.S.C. §2162 Restricted Data",
                reason=(
                    "AEA 42 U.S.C. §2162: Document contains Restricted Data (RD) under the "
                    "Atomic Energy Act without DOE Q clearance authorization. Restricted Data "
                    "— all data concerning the design, production, or use of nuclear weapons, "
                    "special nuclear material production, and nuclear material properties useful "
                    "for weapons — is classified at birth under the AEA and may only be accessed "
                    "by persons holding a current DOE Q (Top Secret equivalent) clearance."
                ),
                filter_name=self.FILTER_NAME,
            )

        # Formerly Restricted Data (FRD)
        if classification == "FRD" and not doc.get("l_clearance", False):
            return FilterResult(
                decision="DENIED",
                regulation="Formerly Restricted Data (FRD)",
                reason=(
                    "AEA / DoD: Document contains Formerly Restricted Data (FRD) without DOE L "
                    "clearance or DoD equivalent. Formerly Restricted Data has been jointly "
                    "determined by DOE and DoD to relate primarily to military applications of "
                    "nuclear technology and transferred to the DoD classification system. Access "
                    "to FRD requires at minimum a DOE L clearance (Secret equivalent) or "
                    "equivalent DoD clearance with appropriate need-to-know."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 10 CFR §73.21 — Safeguards Information
        if safeguards_info and not doc.get("nrc_authorized_access", False):
            return FilterResult(
                decision="DENIED",
                regulation="10 CFR §73.21",
                reason=(
                    "NRC 10 CFR §73.21: Document contains Safeguards Information (SGI) without "
                    "NRC-authorized access. Safeguards information — including physical protection "
                    "plans, security measures, vulnerability assessments, and security inspection "
                    "results for nuclear power plants, fuel cycle facilities, and special nuclear "
                    "material — may only be disclosed to persons with NRC-authorized access under "
                    "10 CFR §73.21. Unauthorized disclosure is a regulatory violation."
                ),
                filter_name=self.FILTER_NAME,
            )

        # SUNSI — Sensitive Unclassified Nuclear Information
        if sunsi_data and not doc.get("need_to_know_verified", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="SUNSI Controls",
                reason=(
                    "NRC SUNSI Controls: Document contains Sensitive Unclassified Nuclear "
                    "Security Information (SUNSI) without verified need-to-know. SUNSI "
                    "encompasses unclassified information that, if disclosed, could compromise "
                    "the security of nuclear facilities, materials, or activities. The NRC "
                    "requires need-to-know verification before SUNSI is shared even with "
                    "authorized personnel; human review is required to verify the recipient's "
                    "legitimate need for this information."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="AEA 42 U.S.C. §2162; 10 CFR §73.21",
            reason=(
                "Document satisfies nuclear classification and safeguards information access "
                "controls under the Atomic Energy Act and 10 CFR §73.21 safeguards requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 4 — NuclearCrossBorderFilter
#            Nuclear Non-Proliferation and Export Controls
#            (10 CFR Part 110; NPT Art. III; 42 U.S.C. §2153)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NuclearCrossBorderFilter:
    """Enforces nuclear non-proliferation and export control requirements.

    10 CFR Part 110: Nuclear technology export to non-NPT country without
    export license → DENIED.

    NPT Art. III / IAEA Safeguards: Fissile material transfer without IAEA
    safeguards agreement → DENIED.

    42 U.S.C. §2153 (123 Agreement): Nuclear cooperation with CN/RU/KP/IR
    without 123 Agreement → DENIED.

    NRC Sensitive Countries: Dual-use nuclear items to NRC-sensitive countries
    without DOE/NRC review → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "NuclearCrossBorderFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate nuclear non-proliferation and export control requirements for *doc*.

        Evaluation order
        ----------------
        1. destination_country not in NPT_MEMBER_STATES without
           nrc_part110_export_license → DENIED
           (10 CFR Part 110 nuclear export license).
        2. is_fissile_material_transfer without iaea_safeguards → DENIED
           (NPT Article III / IAEA safeguards agreement).
        3. destination_country in RESTRICTED_NUCLEAR_COUNTRIES without
           us_123_agreement → DENIED
           (42 U.S.C. §2153 nuclear cooperation agreement).
        4. destination_country in NRC_SENSITIVE_COUNTRIES with
           is_dual_use_nuclear_item without doe_nrc_review → REQUIRES_HUMAN_REVIEW
           (NRC/DOE sensitive country enhanced review).
        5. Otherwise → PERMITTED.
        """
        destination_country = doc.get("destination_country", "")
        is_fissile_material_transfer = doc.get("is_fissile_material_transfer", False)
        is_dual_use_nuclear_item = doc.get("is_dual_use_nuclear_item", False)

        # 10 CFR Part 110 — Nuclear Export License for Non-NPT Destinations
        if destination_country and destination_country not in NPT_MEMBER_STATES:
            if not doc.get("nrc_part110_export_license", False):
                return FilterResult(
                    decision="DENIED",
                    regulation="10 CFR Part 110",
                    reason=(
                        f"NRC 10 CFR Part 110: Nuclear technology export to '{destination_country}' — "
                        f"a country not on the NPT member states list — without a valid NRC export "
                        f"license under 10 CFR Part 110 (Export and Import of Nuclear Equipment and "
                        f"Material). Exports of nuclear material, equipment, and technology to "
                        f"non-NPT destinations require prior NRC export license approval to ensure "
                        f"non-proliferation safeguards are in place."
                    ),
                    filter_name=self.FILTER_NAME,
                )

        # NPT Article III — IAEA Safeguards Agreement
        if is_fissile_material_transfer and not doc.get("iaea_safeguards", False):
            return FilterResult(
                decision="DENIED",
                regulation="NPT Article III / IAEA Safeguards",
                reason=(
                    "NPT Article III / IAEA Safeguards: Fissile material transfer without "
                    "verification of an applicable IAEA safeguards agreement. The Treaty on the "
                    "Non-Proliferation of Nuclear Weapons (NPT) Article III requires that "
                    "non-nuclear-weapon state recipients accept IAEA safeguards on all nuclear "
                    "activities as a condition of receiving nuclear assistance. Transfers of "
                    "fissile material without IAEA safeguards verification are prohibited."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 42 U.S.C. §2153 — 123 Agreement Requirement
        if destination_country in RESTRICTED_NUCLEAR_COUNTRIES and not doc.get("us_123_agreement", False):
            return FilterResult(
                decision="DENIED",
                regulation="42 U.S.C. §2153 (123 Agreement)",
                reason=(
                    f"AEA 42 U.S.C. §2153: Nuclear cooperation with '{destination_country}' without "
                    f"a valid U.S. nuclear cooperation agreement (123 Agreement). Section 123 of "
                    f"the Atomic Energy Act requires that significant nuclear transfers to foreign "
                    f"countries be authorized by a bilateral nuclear cooperation agreement that "
                    f"includes non-proliferation commitments, retransfer consent rights, physical "
                    f"security requirements, and IAEA safeguards. CN/RU/KP/IR do not have current "
                    f"U.S. 123 Agreements in good standing."
                ),
                filter_name=self.FILTER_NAME,
            )

        # NRC Sensitive Countries — Dual-Use Nuclear Items
        if is_dual_use_nuclear_item and destination_country in NRC_SENSITIVE_COUNTRIES:
            if not doc.get("doe_nrc_review", False):
                return FilterResult(
                    decision="REQUIRES_HUMAN_REVIEW",
                    regulation="NRC/DOE Sensitive Country Review",
                    reason=(
                        f"NRC/DOE Sensitive Country Controls: Dual-use nuclear item transfer to "
                        f"NRC-listed sensitive country '{destination_country}' without DOE/NRC "
                        f"enhanced review. The NRC and DOE require enhanced review for exports of "
                        f"dual-use nuclear items — items with both civilian and weapons-related "
                        f"applications — to sensitive countries including CN, RU, KP, IR, SY, CU, "
                        f"SD, and MM. Human review is required to assess proliferation risk and "
                        f"verify compliance with applicable export control requirements."
                    ),
                    filter_name=self.FILTER_NAME,
                )

        return FilterResult(
            decision="PERMITTED",
            regulation="10 CFR Part 110; NPT Art. III; 42 U.S.C. §2153",
            reason=(
                "Document satisfies nuclear non-proliferation and export control requirements "
                "under 10 CFR Part 110, NPT Article III IAEA safeguards, and 42 U.S.C. §2153 "
                "nuclear cooperation agreement requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------


def run_pipeline(doc: dict) -> list[FilterResult]:
    """Run all four nuclear NRC compliance filter layers against *doc*.

    Returns a list of FilterResult objects, one per layer evaluated.  The
    pipeline short-circuits on the first DENIED decision; subsequent filters
    are not evaluated for denied documents.
    """
    filters = [
        NRCLicensingFilter(),
        NRCRadiationProtectionFilter(),
        NDAClassifiedFilter(),
        NuclearCrossBorderFilter(),
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
    print("=== Nuclear Energy / NRC Compliance RAG Pipeline — Demo ===\n")

    # --- Power reactor without operating license ---
    doc_no_license = {
        "doc_id": "nrc-001",
        "facility_type": "power_reactor",
        "nrc_part50_license": False,
    }
    print("Document: Power reactor without NRC Part 50 operating license")
    for r in run_pipeline(doc_no_license):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Occupational dose exceedance ---
    doc_dose_exceeded = {
        "doc_id": "nrc-002",
        "occupational_dose_rem": 6.5,
        "alara_documented": True,
    }
    print("Document: Occupational dose exceeding 5 rem annual limit")
    for r in run_pipeline(doc_dose_exceeded):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Restricted Data without Q clearance ---
    doc_rd_no_clearance = {
        "doc_id": "nrc-003",
        "classification": "RD",
        "q_clearance": False,
    }
    print("Document: Restricted Data without Q clearance")
    for r in run_pipeline(doc_rd_no_clearance):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Nuclear export to non-NPT country without license ---
    doc_non_npt_export = {
        "doc_id": "nrc-004",
        "destination_country": "KP",
        "nrc_part110_export_license": False,
    }
    print("Document: Nuclear technology export to non-NPT country without Part 110 license")
    for r in run_pipeline(doc_non_npt_export):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Research reactor without confirmed §50.21(c) license (REQUIRES_HUMAN_REVIEW) ---
    doc_research_reactor = {
        "doc_id": "nrc-005",
        "facility_type": "research_reactor",
        "nrc_part50_license": False,
    }
    print("Document: Research reactor without confirmed §50.21(c) license type")
    for r in run_pipeline(doc_research_reactor):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Fully compliant nuclear document ---
    doc_compliant = {
        "doc_id": "nrc-006",
        "facility_type": "power_reactor",
        "nrc_part50_license": True,
        "is_radioactive_material_transport": True,
        "nrc_part71_cert": True,
        "occupational_dose_rem": 2.1,
        "public_dose_mrem": 15,
        "alara_documented": True,
        "effluent_within_appendix_b": True,
        "classification": "UNCLASSIFIED",
        "safeguards_info": False,
        "sunsi_data": False,
        "destination_country": "JP",
        "is_fissile_material_transfer": False,
        "is_dual_use_nuclear_item": False,
    }
    print("Document: Fully compliant nuclear document")
    for r in run_pipeline(doc_compliant):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()
