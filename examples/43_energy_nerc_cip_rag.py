"""
Energy Sector / NERC CIP Compliance RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pre-filter for platforms
that process documents related to bulk electric system (BES) operations, energy
markets, critical-infrastructure cybersecurity, and cross-border energy data
transfers.  Four independent filter layers run sequentially; a document must
pass all four to be returned to the caller.

Commercial use cases:

  +--------------------------------------------------------------+--------------------------------------------+
  | Platform / Product                                           | Applicable Regulation(s)                   |
  +--------------------------------------------------------------+--------------------------------------------+
  | Bulk electric system (BES) operations and SCADA platforms    | NERC CIP-007-6; CIP-005-7; CIP-006-6      |
  | Energy market compliance and OASIS trading platforms         | FERC Order 888/889; 18 CFR §1c.2          |
  | Electric grid cybersecurity monitoring and analytics         | DOE 100-Day Plan; CISA ICS-CERT baseline   |
  | AI/ML-driven grid optimisation and demand-response systems   | NIST AI RMF Energy Sector Profile (DOE)    |
  | Interstate natural gas pipeline management platforms         | FERC Gas Tariff; Natural Gas Act §7        |
  | Hydropower dam safety and compliance systems                 | FERC Part 12 dam safety inspections        |
  | Cross-border electricity export compliance platforms         | FPA §202(e); EO 13873 / DOE ICTS Rule      |
  | LNG terminal data management and export authorisation        | Natural Gas Act §3 DOE LNG authorisation   |
  | EU energy grid cross-sector risk and NIS2 platforms          | NIS2 Directive 2022/2555 Art. 21           |
  | E-ISAC / CRISP threat intelligence sharing platforms         | DOE CESER; CRISP programme sharing rules   |
  +--------------------------------------------------------------+--------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — NERCCIPFilter
      (NERC CIP — Critical Infrastructure Protection Standards for the
       Bulk Electric System; enforced by FERC and regional reliability
       organisations such as NERC, WECC, and SERC)
      Controls access to documents involving BES Cyber Systems, Electronic
      Security Perimeters, Physical Security Plans, and Incident Response
      Plans, enforcing system security management, ESP access controls,
      physical access controls, and E-ISAC incident reporting obligations.

      NERC CIP-007-6 (System Security Management): BES Cyber Systems must
      implement ports and services management, security patch management, and
      malicious code prevention controls.  Documents describing BES Cyber
      Systems without CIP-007-6 System Security Management controls are
      denied.

      NERC CIP-005-7 (Electronic Security Perimeters): Electronic Security
      Perimeters protecting BES Cyber Systems must enforce ESP access
      controls and remote access management.  Documents describing ESPs
      without CIP-005-7 compliance are denied.

      NERC CIP-006-6 (Physical Security of BES Cyber Systems): BES Cyber
      Systems must have documented Physical Security Plans covering physical
      access controls.  Documents describing BES assets without CIP-006-6
      compliance are denied.

      NERC CIP-008-6 (Incident Reporting and Response Planning): BES Cyber
      Incident Response Plans must provide for reporting to E-ISAC within
      1 hour of a Cyber Security Incident.  Documents with Incident Response
      Plans not meeting CIP-008-6 reporting thresholds are escalated to
      REQUIRES_HUMAN_REVIEW.

  Layer 2 — FERCEnergyFilter
      (Federal Energy Regulatory Commission — Orders, Rules, and Tariffs
       governing energy markets, transmission access, and reliability;
       authority derived from the Federal Power Act (FPA) and the
       Natural Gas Act (NGA))
      Controls access to documents involving energy trading, market
      operations, interstate transmission, natural gas pipelines, and
      hydropower facilities, enforcing OASIS compliance, anti-manipulation
      safeguards, Gas Tariff requirements, and dam safety inspections.

      FERC Order 888/889 OASIS (Open Access Transmission Tariff): Electric
      utilities providing transmission service under Order 888 must post
      transmission information via an Open Access Same-Time Information
      System (OASIS).  Documents describing energy trading without OASIS
      compliance are denied.

      FERC Anti-Manipulation Rule 18 CFR §1c.2: No entity subject to FERC
      jurisdiction may engage in, or facilitate, energy market manipulation
      using deceptive practices or contrivances.  Documents describing market
      activities without Anti-Manipulation Rule safeguards are denied.

      FERC Gas Tariff / Natural Gas Act §7 Certificate: Interstate natural
      gas pipeline operators must hold a FERC certificate of public
      convenience and necessity and comply with their accepted Gas Tariff.
      Documents describing interstate gas pipeline data without Gas Tariff
      compliance are denied.

      FERC Part 12 Dam Safety (18 CFR Part 12): FERC-licensed hydropower
      facilities must undergo periodic dam safety inspections and maintain
      current inspection reports.  Documents describing hydropower facilities
      without a current FERC Part 12 dam safety review are escalated to
      REQUIRES_HUMAN_REVIEW.

  Layer 3 — DOECybersecurityFilter
      (U.S. Department of Energy (DOE) / CISA energy-sector cybersecurity
       directives; NIST AI Risk Management Framework (AI RMF) energy sector
       profile; DOE CESER / E-ISAC / CRISP threat sharing programmes)
      Controls access to documents involving Operational Technology (OT)
      systems, Industrial Control Systems (ICS), AI/ML applications in grid
      operations, and grid modernisation data sharing.

      DOE 100-Day Plan (Electricity Subsector OT Monitoring): Electric
      utility owners and operators are directed to deploy cybersecurity
      monitoring technologies for OT environments as part of DOE's 100-Day
      Plan to safeguard the electricity subsector.  Documents describing OT
      systems without DOE 100-Day Plan cybersecurity controls are denied.

      CISA ICS-CERT Baseline Controls: Industrial Control Systems operated
      in critical-infrastructure sectors must implement mitigations published
      in applicable ICS-CERT Advisories.  Documents describing ICS without
      ICS-CERT baseline controls are denied.

      NIST AI RMF Energy Sector Profile (DOE AI/ML for Grid
      Modernisation): AI and ML systems deployed in grid operations must
      align with the NIST AI Risk Management Framework energy sector profile
      as promoted by DOE.  Documents describing energy AI/ML systems without
      an NIST AI RMF energy sector alignment assessment are denied.

      DOE CESER Threat Sharing / E-ISAC / CRISP: Grid modernisation data
      shared across utility boundaries should participate in DOE CESER-
      sponsored threat sharing programmes (E-ISAC or CRISP) to ensure
      collective defence.  Documents describing grid modernisation data
      without DOE CESER threat sharing participation are escalated to
      REQUIRES_HUMAN_REVIEW.

  Layer 4 — EnergyCrossBorderFilter
      (Federal Power Act §202(e); Executive Order 13873 / DOE ICTS Rule;
       Natural Gas Act §3; EU NIS2 Directive 2022/2555 Art. 21)
      Controls access to documents involving cross-border electricity
      exports, energy infrastructure data transfers to adversarial nations,
      LNG terminal data, and EU cross-sector energy risk management.

      FPA §202(e) — FERC Jurisdictional Electricity Export: Section 202(e)
      of the Federal Power Act requires FERC authorisation before electricity
      is exported from the United States to non-NAFTA countries.  Documents
      describing FERC-jurisdictional electricity exports to non-NAFTA
      destinations without export authorisation are denied.

      EO 13873 / DOE ICTS Rule — Critical Energy Infrastructure Data to
      Adversarial Nations: Executive Order 13873 and the DOE ICTS Rule
      prohibit transactions involving bulk power system equipment or data
      with adversarial-nation entities (China, Russia, North Korea, Iran).
      Documents transmitting critical energy infrastructure data to
      adversarial nations (CN/RU/KP/IR) are denied.

      Natural Gas Act §3 — DOE LNG Export Authorisation: Exports of
      liquefied natural gas (LNG) from the United States require DOE export
      authorisation under Natural Gas Act §3.  Documents describing LNG
      export terminal data without a confirmed DOE LNG export authorisation
      are denied.

      EU NIS2 Directive 2022/2555 Art. 21 (Cross-Sector Risk Measures):
      Energy entities that are essential entities under NIS2 must implement
      cross-sector risk management measures including incident response,
      supply-chain security, and access control.  Documents describing EU
      energy data without NIS2 Art. 21 cross-sector risk measures are
      escalated to REQUIRES_HUMAN_REVIEW.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Nations treated as adversarial for energy infrastructure transfers under
#: EO 13873 and the DOE ICTS Rule.
ENERGY_ADVERSARIAL_NATIONS: frozenset[str] = frozenset({"CN", "RU", "KP", "IR"})

#: NAFTA member countries exempt from FERC §202(e) electricity export
#: authorisation requirement (US, Canada, Mexico).
NAFTA_MEMBERS: frozenset[str] = frozenset({"US", "CA", "MX"})


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document.

    Fields
    ------
    decision     : "PERMITTED", "DENIED", "REQUIRES_HUMAN_REVIEW", or "REDACTED"
    regulation   : Short citation string (e.g. "NERC CIP-007-6")
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
# Layer 1 — NERCCIPFilter
#            NERC CIP Critical Infrastructure Protection Standards
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NERCCIPFilter:
    """Enforces NERC CIP standards for Bulk Electric System Cyber Systems.

    NERC CIP-007-6: BES Cyber Systems without System Security Management
    controls (ports/services, security patches, malicious code prevention)
    are denied.

    NERC CIP-005-7: Electronic Security Perimeters without ESP access
    controls and remote access management are denied.

    NERC CIP-006-6: BES Cyber Systems without Physical Security Plans
    covering physical access controls are denied.

    NERC CIP-008-6: Incident Response Plans not providing for E-ISAC
    reporting within 1 hour of a Cyber Security Incident are escalated to
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "NERCCIPFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate NERC CIP compliance controls for *doc*.

        Evaluation order
        ----------------
        1. BES Cyber System without CIP-007-6 System Security Management →
           DENIED (ports/services + security patches + malicious code).
        2. Electronic Security Perimeter without CIP-005-7 compliance →
           DENIED (ESP access controls + remote access management).
        3. Physical Security Plan without CIP-006-6 compliance →
           DENIED (physical access controls for BES Cyber Systems).
        4. Incident Response Plan not meeting CIP-008-6 E-ISAC reporting →
           REQUIRES_HUMAN_REVIEW (1-hour E-ISAC reporting threshold).
        5. Otherwise → PERMITTED.
        """
        is_bes_cyber = doc.get("is_bes_cyber_system", False)
        is_esp = doc.get("is_electronic_security_perimeter", False)
        has_physical_plan = doc.get("has_physical_security_plan", False)
        has_irp = doc.get("has_incident_response_plan", False)

        # CIP-007-6 — System Security Management
        if is_bes_cyber and not doc.get("cip_007_6_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="NERC CIP-007-6",
                reason=(
                    "NERC CIP-007-6: BES Cyber System lacks System Security Management "
                    "controls. CIP-007-6 requires ports and services management, security "
                    "patch management, and malicious code prevention for all BES Cyber "
                    "Systems."
                ),
                filter_name=self.FILTER_NAME,
            )

        # CIP-005-7 — Electronic Security Perimeter
        if is_esp and not doc.get("cip_005_7_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="NERC CIP-005-7",
                reason=(
                    "NERC CIP-005-7: Electronic Security Perimeter lacks required access "
                    "controls and remote access management. CIP-005-7 mandates ESP access "
                    "control policies and multi-factor authentication for all interactive "
                    "remote access to high and medium impact BES Cyber Systems."
                ),
                filter_name=self.FILTER_NAME,
            )

        # CIP-006-6 — Physical Security of BES Cyber Systems
        if has_physical_plan and not doc.get("cip_006_6_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="NERC CIP-006-6",
                reason=(
                    "NERC CIP-006-6: Physical Security Plan does not satisfy CIP-006-6 "
                    "requirements. Physical access controls must restrict and log access "
                    "to Physical Security Perimeters housing BES Cyber Systems."
                ),
                filter_name=self.FILTER_NAME,
            )

        # CIP-008-6 — Incident Reporting (E-ISAC within 1 hour)
        if has_irp and not doc.get("cip_008_6_eisac_reporting", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="NERC CIP-008-6",
                reason=(
                    "NERC CIP-008-6: Incident Response Plan does not meet E-ISAC reporting "
                    "requirements. CIP-008-6 requires reporting of Cyber Security Incidents "
                    "to E-ISAC within 1 hour of identification."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="NERC CIP",
            reason=(
                "Document satisfies NERC CIP Critical Infrastructure Protection "
                "standards for Bulk Electric System operations."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 2 — FERCEnergyFilter
#            FERC Energy Market and Reliability Rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FERCEnergyFilter:
    """Enforces FERC energy market, transmission, and reliability rules.

    FERC Order 888/889 OASIS: Energy trading without OASIS compliance
    is denied.

    FERC Anti-Manipulation Rule 18 CFR §1c.2: Market activities without
    Anti-Manipulation Rule safeguards are denied.

    FERC Gas Tariff / Natural Gas Act §7: Interstate gas pipeline data
    without Gas Tariff compliance is denied.

    FERC Part 12 Dam Safety: Hydropower facilities without a current
    FERC Part 12 dam safety review are escalated to REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "FERCEnergyFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate FERC energy market and reliability rules for *doc*.

        Evaluation order
        ----------------
        1. Energy trading without OASIS compliance → DENIED
           (FERC Order 888/889).
        2. Market activity without anti-manipulation safeguards → DENIED
           (FERC 18 CFR §1c.2).
        3. Interstate gas pipeline data without Gas Tariff compliance →
           DENIED (FERC Gas Tariff / NGA §7).
        4. Hydropower facility without current FERC Part 12 dam safety
           review → REQUIRES_HUMAN_REVIEW (18 CFR Part 12).
        5. Otherwise → PERMITTED.
        """
        is_energy_trading = doc.get("is_energy_trading_data", False)
        is_market_activity = doc.get("is_market_activity", False)
        is_interstate_gas = doc.get("is_interstate_gas_pipeline", False)
        is_hydropower = doc.get("is_hydropower_facility", False)

        # FERC Order 888/889 — OASIS compliance
        if is_energy_trading and not doc.get("oasis_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="FERC Order 888/889 OASIS",
                reason=(
                    "FERC Order 888/889: Energy trading data lacks Open Access Same-Time "
                    "Information System (OASIS) compliance. Electric utilities must post "
                    "transmission availability and pricing information via OASIS under "
                    "the Open Access Transmission Tariff."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FERC Anti-Manipulation Rule 18 CFR §1c.2
        if is_market_activity and not doc.get("anti_manipulation_safeguards", False):
            return FilterResult(
                decision="DENIED",
                regulation="FERC 18 CFR §1c.2",
                reason=(
                    "FERC 18 CFR §1c.2 Anti-Manipulation Rule: Market activity data lacks "
                    "anti-manipulation safeguards. No entity subject to FERC jurisdiction "
                    "may engage in deceptive practices in connection with the purchase, "
                    "sale, or transmission of electric energy or natural gas."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FERC Gas Tariff / Natural Gas Act §7 Certificate
        if is_interstate_gas and not doc.get("ferc_gas_tariff_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="FERC Gas Tariff / Natural Gas Act §7",
                reason=(
                    "FERC Gas Tariff / Natural Gas Act §7: Interstate natural gas pipeline "
                    "data lacks Gas Tariff compliance. Pipeline operators must hold a FERC "
                    "certificate of public convenience and necessity under NGA §7 and comply "
                    "with their FERC-accepted Gas Tariff."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FERC Part 12 Dam Safety — 18 CFR Part 12
        if is_hydropower and not doc.get("ferc_part12_dam_safety_current", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="FERC 18 CFR Part 12",
                reason=(
                    "FERC 18 CFR Part 12: Hydropower facility lacks a current FERC Part 12 "
                    "dam safety inspection. FERC-licensed facilities must maintain current "
                    "independent consultant inspection reports and comply with dam safety "
                    "directives."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="FERC Energy Rules",
            reason=(
                "Document satisfies FERC energy market, transmission, and reliability "
                "requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 3 — DOECybersecurityFilter
#            DOE/CISA Energy Sector Cybersecurity Directives
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DOECybersecurityFilter:
    """Enforces DOE and CISA energy sector cybersecurity controls.

    DOE 100-Day Plan (Electricity Subsector OT Monitoring): OT without
    DOE 100-Day Plan cybersecurity controls is denied.

    CISA ICS-CERT Baseline Controls: ICS without ICS-CERT baseline
    controls is denied.

    NIST AI RMF Energy Sector Profile: Energy AI/ML systems without
    NIST AI RMF energy sector alignment are denied.

    DOE CESER Threat Sharing / E-ISAC / CRISP: Grid modernisation data
    without DOE CESER threat sharing participation is escalated to
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "DOECybersecurityFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate DOE/CISA energy sector cybersecurity controls for *doc*.

        Evaluation order
        ----------------
        1. OT without DOE 100-Day Plan cybersecurity controls → DENIED
           (electricity subsector OT monitoring).
        2. ICS without CISA ICS-CERT baseline controls → DENIED
           (ICS-CERT Advisory mitigations required).
        3. Energy AI/ML system without NIST AI RMF energy sector profile →
           DENIED (DOE AI/ML for Grid Modernisation).
        4. Grid modernisation data without DOE CESER threat sharing →
           REQUIRES_HUMAN_REVIEW (E-ISAC/CRISP programme).
        5. Otherwise → PERMITTED.
        """
        is_ot = doc.get("is_energy_ot_system", False)
        is_ics = doc.get("is_energy_ics", False)
        is_ai_ml = doc.get("is_energy_ai_ml_system", False)
        is_grid_modernisation = doc.get("is_grid_modernisation_data", False)

        # DOE 100-Day Plan — OT Monitoring Controls
        if is_ot and not doc.get("doe_100day_plan_controls", False):
            return FilterResult(
                decision="DENIED",
                regulation="DOE 100-Day Plan (Electricity OT)",
                reason=(
                    "DOE 100-Day Plan: Energy sector OT system lacks required cybersecurity "
                    "monitoring controls. The DOE 100-Day Plan directs electric utility "
                    "owners and operators to deploy OT-specific monitoring technologies to "
                    "improve visibility and detection in the electricity subsector."
                ),
                filter_name=self.FILTER_NAME,
            )

        # CISA ICS-CERT Baseline Controls
        if is_ics and not doc.get("ics_cert_baseline_controls", False):
            return FilterResult(
                decision="DENIED",
                regulation="CISA ICS-CERT Baseline Controls",
                reason=(
                    "CISA ICS-CERT: Industrial Control System lacks required baseline "
                    "cybersecurity controls. ICS-CERT Advisory mitigations must be "
                    "implemented for all critical-infrastructure ICS to reduce known "
                    "vulnerabilities and attack surface."
                ),
                filter_name=self.FILTER_NAME,
            )

        # NIST AI RMF Energy Sector Profile
        if is_ai_ml and not doc.get("nist_ai_rmf_energy_profile", False):
            return FilterResult(
                decision="DENIED",
                regulation="NIST AI RMF Energy Sector Profile (DOE)",
                reason=(
                    "NIST AI RMF Energy Sector Profile: Energy AI/ML system lacks an "
                    "NIST AI Risk Management Framework energy sector profile alignment "
                    "assessment. DOE's AI/ML for Grid Modernisation programme requires "
                    "AI systems in grid operations to align with the AI RMF."
                ),
                filter_name=self.FILTER_NAME,
            )

        # DOE CESER / E-ISAC / CRISP Threat Sharing
        if is_grid_modernisation and not doc.get("doe_ceser_threat_sharing", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="DOE CESER / E-ISAC / CRISP",
                reason=(
                    "DOE CESER Threat Sharing: Grid modernisation data lacks DOE CESER "
                    "threat sharing programme participation. Utilities sharing grid "
                    "modernisation data across boundaries should participate in the "
                    "E-ISAC or CRISP threat intelligence sharing programme."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="DOE/CISA Energy Cybersecurity",
            reason=(
                "Document satisfies DOE and CISA energy sector cybersecurity "
                "directive requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 4 — EnergyCrossBorderFilter
#            Cross-Border Energy Data and Infrastructure Export Controls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnergyCrossBorderFilter:
    """Enforces cross-border energy data transfer and export controls.

    FPA §202(e): FERC-jurisdictional electricity exports to non-NAFTA
    countries without authorisation are denied.

    EO 13873 / DOE ICTS Rule: Critical energy infrastructure data to
    adversarial nations (CN/RU/KP/IR) are denied.

    Natural Gas Act §3: LNG export terminal data without DOE LNG export
    authorisation are denied.

    EU NIS2 Directive 2022/2555 Art. 21: EU energy data without NIS2
    Art. 21 cross-sector risk measures are escalated to
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "EnergyCrossBorderFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate cross-border energy export controls for *doc*.

        Evaluation order
        ----------------
        1. FERC-jurisdictional electricity export to non-NAFTA country
           without authorisation → DENIED (FPA §202(e)).
        2. Critical energy infrastructure data to adversarial nation
           (CN/RU/KP/IR) → DENIED (EO 13873 / DOE ICTS Rule).
        3. LNG export terminal data without DOE LNG export authorisation →
           DENIED (Natural Gas Act §3).
        4. EU energy data without NIS2 Art. 21 cross-sector risk measures →
           REQUIRES_HUMAN_REVIEW (NIS2 Directive 2022/2555 Art. 21).
        5. Otherwise → PERMITTED.
        """
        destination = doc.get("destination_country", "")
        is_ferc_electricity_export = doc.get("is_ferc_electricity_export", False)
        is_critical_energy_data = doc.get("is_critical_energy_infrastructure_data", False)
        is_lng_terminal = doc.get("is_lng_export_terminal_data", False)
        is_eu_energy = doc.get("is_eu_energy_data", False)

        # FPA §202(e) — FERC electricity export to non-NAFTA country
        if (
            is_ferc_electricity_export
            and destination not in NAFTA_MEMBERS
            and not doc.get("ferc_export_authorisation", False)
        ):
            return FilterResult(
                decision="DENIED",
                regulation="FPA §202(e)",
                reason=(
                    f"FPA §202(e): FERC-jurisdictional electricity export to non-NAFTA "
                    f"destination '{destination}' lacks FERC export authorisation. "
                    f"Section 202(e) of the Federal Power Act requires prior FERC "
                    f"authorisation for electricity exports from the United States to "
                    f"non-NAFTA countries."
                ),
                filter_name=self.FILTER_NAME,
            )

        # EO 13873 / DOE ICTS Rule — adversarial nation energy data transfer
        if is_critical_energy_data and destination in ENERGY_ADVERSARIAL_NATIONS:
            return FilterResult(
                decision="DENIED",
                regulation="EO 13873 / DOE ICTS Rule",
                reason=(
                    f"EO 13873 / DOE ICTS Rule: Critical energy infrastructure data "
                    f"transfer to adversarial nation '{destination}' is prohibited. "
                    f"Executive Order 13873 and the DOE ICTS Rule prohibit bulk power "
                    f"system data transactions with entities from China, Russia, North "
                    f"Korea, and Iran."
                ),
                filter_name=self.FILTER_NAME,
            )

        # Natural Gas Act §3 — DOE LNG export authorisation
        if is_lng_terminal and not doc.get("doe_lng_export_authorisation", False):
            return FilterResult(
                decision="DENIED",
                regulation="Natural Gas Act §3",
                reason=(
                    "Natural Gas Act §3: LNG export terminal data lacks a confirmed DOE "
                    "LNG export authorisation. Exports of liquefied natural gas from the "
                    "United States require DOE authorisation under Natural Gas Act §3, "
                    "including both FTA and non-FTA country authorisations where required."
                ),
                filter_name=self.FILTER_NAME,
            )

        # EU NIS2 Directive 2022/2555 Art. 21 — cross-sector risk measures
        if is_eu_energy and not doc.get("nis2_art21_risk_measures", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="EU NIS2 Directive 2022/2555 Art. 21",
                reason=(
                    "EU NIS2 Directive 2022/2555 Art. 21: EU energy entity data lacks "
                    "evidence of NIS2 Art. 21 cross-sector risk management measures. "
                    "Essential energy entities must implement incident response, supply-"
                    "chain security, access control, and encryption under Directive "
                    "2022/2555 Art. 21."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="FPA §202(e); EO 13873; NGA §3; NIS2 Art. 21",
            reason=(
                "Document satisfies cross-border energy data transfer and export "
                "control requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------


def run_pipeline(doc: dict) -> list[FilterResult]:
    """Run all four energy / NERC CIP filter layers against *doc*.

    Returns a list of FilterResult objects, one per layer evaluated.  The
    pipeline short-circuits on the first DENIED decision; subsequent filters
    are not evaluated for denied documents.
    """
    filters = [
        NERCCIPFilter(),
        FERCEnergyFilter(),
        DOECybersecurityFilter(),
        EnergyCrossBorderFilter(),
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
    print("=== Energy Sector / NERC CIP Compliance RAG Pipeline — Demo ===\n")

    # --- BES Cyber System without CIP-007-6 controls ---
    doc_bes_no_ssm = {
        "doc_id": "bes-001",
        "is_bes_cyber_system": True,
        "cip_007_6_compliant": False,
    }
    print("Document: BES Cyber System without CIP-007-6 System Security Management")
    for r in run_pipeline(doc_bes_no_ssm):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Energy trading data without OASIS compliance ---
    doc_trading_no_oasis = {
        "doc_id": "ferc-002",
        "is_energy_trading_data": True,
        "oasis_compliant": False,
    }
    print("Document: Energy trading data without OASIS compliance")
    for r in run_pipeline(doc_trading_no_oasis):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Energy OT without DOE 100-Day Plan controls ---
    doc_ot_no_doe = {
        "doc_id": "doe-003",
        "is_energy_ot_system": True,
        "doe_100day_plan_controls": False,
    }
    print("Document: Energy OT system without DOE 100-Day Plan controls")
    for r in run_pipeline(doc_ot_no_doe):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Critical energy infrastructure data to China ---
    doc_china_export = {
        "doc_id": "export-004",
        "is_critical_energy_infrastructure_data": True,
        "destination_country": "CN",
    }
    print("Document: Critical energy infrastructure data to China (adversarial nation)")
    for r in run_pipeline(doc_china_export):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Incident Response Plan without CIP-008-6 E-ISAC reporting ---
    doc_irp_no_eisac = {
        "doc_id": "cip-005",
        "has_incident_response_plan": True,
        "cip_008_6_eisac_reporting": False,
    }
    print("Document: Incident Response Plan without CIP-008-6 E-ISAC reporting")
    for r in run_pipeline(doc_irp_no_eisac):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Fully compliant energy document ---
    doc_compliant = {
        "doc_id": "compliant-006",
        # Layer 1 — NERC CIP
        "is_bes_cyber_system": True,
        "cip_007_6_compliant": True,
        "is_electronic_security_perimeter": True,
        "cip_005_7_compliant": True,
        "has_physical_security_plan": True,
        "cip_006_6_compliant": True,
        "has_incident_response_plan": True,
        "cip_008_6_eisac_reporting": True,
        # Layer 2 — FERC
        "is_energy_trading_data": True,
        "oasis_compliant": True,
        "is_market_activity": True,
        "anti_manipulation_safeguards": True,
        "is_interstate_gas_pipeline": True,
        "ferc_gas_tariff_compliant": True,
        "is_hydropower_facility": True,
        "ferc_part12_dam_safety_current": True,
        # Layer 3 — DOE/CISA
        "is_energy_ot_system": True,
        "doe_100day_plan_controls": True,
        "is_energy_ics": True,
        "ics_cert_baseline_controls": True,
        "is_energy_ai_ml_system": True,
        "nist_ai_rmf_energy_profile": True,
        "is_grid_modernisation_data": True,
        "doe_ceser_threat_sharing": True,
        # Layer 4 — Cross-border
        "destination_country": "GB",
        "is_ferc_electricity_export": False,
        "is_critical_energy_infrastructure_data": False,
        "is_lng_export_terminal_data": False,
        "is_eu_energy_data": False,
    }
    print("Document: Fully compliant energy system")
    for r in run_pipeline(doc_compliant):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()
    print("Demo complete.")
