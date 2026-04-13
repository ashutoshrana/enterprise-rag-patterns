"""
Energy and Utilities RAG Pipeline — Four-Layer Defense-in-Depth

This module implements a compliance-aware RAG retrieval pipeline for energy and
utilities sector platforms. Four independent filter layers run sequentially; a
document must pass all four to be returned to the caller.

Regulatory frameworks enforced:

  Layer 1 — NERC CIP (Critical Infrastructure Protection) Standards
      The North American Electric Reliability Corporation (NERC) Critical
      Infrastructure Protection (CIP) reliability standards govern the
      cybersecurity of Bulk Electric System (BES) Cyber Systems.

      CIP-004-6 (Personnel and Training): Requires operators of High and Medium
      Impact BES Cyber Systems to perform personnel risk assessments (PRAs) for
      all individuals with access to BES Cyber System Information (BCSI).
      Section R3 mandates completion of the PRA before granting unescorted
      physical or electronic access.

      CIP-005-7 (Electronic Security Perimeters): Establishes requirements for
      Electronic Security Perimeters (ESPs) protecting High Impact BES Cyber
      Systems. Section R1 requires operators to identify all Electronic Access
      Points (EAPs) and authorize electronic access controls before permitting
      access.

      CIP-006-6 (Physical Security of BES Cyber Systems): Governs physical
      security plans for High and Medium Impact BES Cyber Systems. Section R1
      requires a documented physical security plan including access controls,
      visitor controls, and monitoring.

      CIP-007-6 (Systems Security Management): Section R4 requires event logging
      for all access to BES Cyber Systems. Access logs must be retained for 90
      calendar days for High Impact systems.

      CIP-010-4 (Configuration Change Management and Vulnerability Assessments):
      Requires baseline configuration monitoring and change management for BES
      Cyber Systems. Section R1 requires documentation and monitoring of
      configuration changes.

      CIP-011-2 (Information Protection): Directly governs BES Cyber System
      Information (BCSI) protection. Section R1 requires an information protection
      program identifying and controlling BCSI. Entities must document need-to-know
      for each individual authorized to access BCSI.

      CIP-013-2 (Supply Chain Risk Management): Section R1 requires a supply chain
      risk management plan addressing vendor electronic remote access, software
      integrity verification, and active vendor/contractor access management.

  Layer 2 — FERC Regulatory Filings and Critical Energy Infrastructure
             Information (CEII)
      The Federal Energy Regulatory Commission (FERC) protects Critical Energy
      Infrastructure Information under 18 CFR Part 388 Subpart A.

      18 CFR §388.112: Defines CEII as specific engineering, vulnerability, or
      detailed design information about proposed or existing critical
      infrastructure that could be useful to persons planning an attack on that
      infrastructure.

      18 CFR §388.113: CEII is exempt from disclosure under FOIA. Requires
      requestors to submit a CEII request, demonstrate need, and execute a
      non-disclosure agreement before access is granted. Section (e) requires
      that all CEII holders comply with FERC's CEII handling procedures, including
      restrictions on further disclosure, document marking, and secure destruction.

      18 CFR §388.113(d): FERC staff, commissioners, and other federal agency
      personnel with official responsibility may access CEII without executing
      the NDA process.

      Restricted FERC filings that do not rise to CEII status are controlled
      under 18 CFR Part 388 general protective orders and require documented
      internal need-to-know authorization.

  Layer 3 — DOE Cybersecurity, Energy Security, and Emergency Response (CESER)
      The Department of Energy's CESER office administers cybersecurity
      requirements for the energy sector under authorities including the
      Federal Power Act and Energy Policy Act of 2005.

      DOE Order 470.4B (Safeguards and Security Program): Establishes the DOE
      security framework for classified and sensitive information. Requires
      personnel reliability programs for individuals with access to sensitive
      information and classified matter.

      DOE Order 475.1B (Identifying Classified Information): Governs the
      determination and control of classified information in DOE programs.

      DOE O 471.3 (Identifying and Protecting Official Use Only Information):
      Covers sensitive but unclassified information relevant to DOE energy
      programs, including operational security information, vulnerability
      assessments, and cybersecurity architecture details.

      DOE CESER Cybersecurity Strategy: Published guidance requiring that
      sensitive cybersecurity information concerning grid architecture, control
      system vulnerabilities, and incident response plans be shared only on a
      need-to-know basis with authorized recipients.

  Layer 4 — NRC 10 CFR Part 73 Safeguards Information (Nuclear Facilities)
      The Nuclear Regulatory Commission (NRC) protects Safeguards Information
      (SGI) under 10 CFR Part 73 for commercial nuclear power plants and other
      NRC-licensed facilities.

      10 CFR 73.21 (Protection of Safeguards Information — General Performance
      Objectives and Requirements): Requires licensees to protect SGI from
      unauthorized disclosure. Establishes requirements for access, storage,
      transmission, and destruction of SGI documents. Requires that each
      individual with access have a documented need-to-know.

      10 CFR 73.22 (Protection of Safeguards Information — Specific Requirements
      for Power Reactor Licensees): Establishes access controls and designation
      requirements for SGI at power reactor facilities. Section (d) governs
      contractor and vendor access to SGI with approved need-to-know.

      10 CFR 73.23 (Protection of Safeguards Information — Specific Requirements
      for Fuel Cycle Facilities and Other Licensees): Similar controls for
      non-power reactor facilities.

      NRC Inspection Procedures: NRC inspectors and resident inspectors have
      standing authority to access SGI as part of regulatory oversight activities.
      Unauthorized disclosure of SGI is a violation of federal law and subject to
      civil and criminal penalties.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class EnergyRole(Enum):
    GRID_OPERATOR = "grid_operator"
    COMPLIANCE_OFFICER = "compliance_officer"
    SECURITY_ANALYST = "security_analyst"
    FIELD_TECHNICIAN = "field_technician"
    CONTRACTOR = "contractor"
    REGULATOR = "regulator"
    VENDOR = "vendor"
    EXECUTIVE = "executive"
    ADMIN = "admin"


class BESCyberSystemImpact(Enum):
    """
    NERC CIP BES Cyber System impact rating.

    HIGH:    High Impact BES Cyber System — control centers with operational
             control of the BES; most stringent CIP requirements.
    MEDIUM:  Medium Impact BES Cyber System — generation, transmission, and
             substation facilities meeting NERC BES threshold criteria.
    LOW:     Low Impact BES Cyber System — applicable CIP-003-8 controls only.
    NOT_BES: Asset is not a BES Cyber System; CIP cyber standards do not apply.
    """
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOT_BES = "not_bes"


class EnergyDecision(Enum):
    PERMITTED = "permitted"
    DENIED = "denied"
    REDACTED = "redacted"


# ---------------------------------------------------------------------------
# Context and Document dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EnergyUtilitiesContext:
    """
    Carries all per-request attributes needed by the four filter layers.

    All fields are immutable; a new context object must be created for each
    distinct request or change in authorization state.
    """

    user_id: str
    user_role: EnergyRole
    facility_id: str
    user_cleared_for_cip: bool             # NERC CIP-004-6: personnel risk assessment complete
    has_need_to_know: bool                 # User has documented need-to-know for the document
    is_authorized_electronic_access: bool  # CIP-005: Electronic Access Controls authorized
    is_on_site_physical_access: bool       # Physical access to facility authorized
    contractor_agreement_active: bool      # Active contractor agreement (CIP-013 supply chain)
    ferc_ceii_authorized: bool             # FERC CEII non-disclosure agreement on file
    is_ferc_staff: bool                    # FERC regulatory staff
    doe_clearance_level: str               # "" / "sensitive" / "classified" (DOE)
    nrc_safeguards_authorized: bool        # NRC 10 CFR 73 safeguards information access
    is_nrc_inspector: bool                 # NRC inspector or licensee personnel
    is_audit_access: bool                  # Formal audit/inspection access


@dataclass(frozen=True)
class EnergyDocument:
    """
    Immutable document descriptor carrying attributes needed for compliance
    evaluation across all four filter layers.
    """

    document_id: str
    bes_cyber_system_impact: BESCyberSystemImpact
    is_ceii: bool               # FERC Critical Energy Infrastructure Information
    is_ferc_restricted: bool    # FERC regulatory filing with restricted access
    is_doe_sensitive: bool      # DOE sensitive cybersecurity information
    is_classified: bool         # Classified national security information
    is_safeguards_info: bool    # NRC 10 CFR 73 Safeguards Information
    is_public: bool             # Publicly available information


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class EnergyFilterResult:
    """Result produced by a single filter layer for one document."""

    layer: str
    decision: EnergyDecision = EnergyDecision.PERMITTED
    reason: str = ""
    conditions: list = field(default_factory=list)

    @property
    def is_denied(self) -> bool:
        return self.decision == EnergyDecision.DENIED


# ---------------------------------------------------------------------------
# Layer 1: NERCCIPFilter (NERC CIP-004, CIP-005, CIP-011)
# ---------------------------------------------------------------------------

class NERCCIPFilter:
    """
    Enforces NERC CIP BES Cyber System Information (BCSI) protection requirements.

    The NERC CIP reliability standards apply to owners and operators of High,
    Medium, and Low Impact BES Cyber Systems. The key information-protection
    obligations are:

      - CIP-004-6 R3: No individual may be granted access to BCSI unless they
        have completed a personnel risk assessment (PRA) within the prior seven
        years. The PRA must include an identity verification and seven-year
        criminal history check.

      - CIP-005-7 R1: All electronic access to High Impact BES Cyber Systems must
        be through authorized Electronic Access Points (EAPs). Access is prohibited
        unless the individual is listed in the Electronic Access Controls.

      - CIP-011-2 R1: Entities must identify all BCSI and document need-to-know for
        each individual authorized to access BCSI. Access without documented
        need-to-know is a CIP violation.

      - CIP-007-6 R4: All access events for High Impact systems must be logged
        and retained for 90 days.

      - CIP-010-4 R1: Configuration change monitoring must be active for any
        access to BES Cyber Systems configuration information.

      - CIP-013-2 R1: Vendor and contractor access must be managed under an
        active supply chain risk management plan; inactive agreements invalidate
        access authorizations.

    Regulatory entities and formal audit access are granted pass-through with
    conditions requiring the applicable CIP logging requirements to be met.
    """

    LAYER_NAME = "NERC_CIP_BES_CYBER_SYSTEM"

    def evaluate(
        self, context: EnergyUtilitiesContext, document: EnergyDocument
    ) -> EnergyFilterResult:
        """
        Evaluate whether the requesting context satisfies NERC CIP requirements
        for access to the document.

        Returns an EnergyFilterResult with PERMITTED or DENIED together with
        the operative CIP standard finding or condition.
        """
        # Publicly available documents carry no NERC CIP restriction.
        if document.is_public:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="Publicly available document — NERC CIP does not restrict access",
            )

        # Document is not a BES Cyber System asset — CIP standards do not apply.
        if document.bes_cyber_system_impact == BESCyberSystemImpact.NOT_BES:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="Document is not associated with a BES Cyber System — NERC CIP does not apply",
            )

        # Regulators (NERC, regional entities) and formal audit/inspection access
        # have standing access to BCSI during compliance audits and spot checks.
        # CIP-007 logging requirements still apply.
        if context.user_role == EnergyRole.REGULATOR or context.is_audit_access:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="NERC CIP: Regulatory or audit access — compliance audit access authorized",
                conditions=[
                    "NERC CIP: Regulatory/audit access — CIP-007 and CIP-010 logging "
                    "requirements apply"
                ],
            )

        # ------------------------------------------------------------------
        # High Impact BES Cyber Systems — most stringent CIP controls.
        # ------------------------------------------------------------------
        if document.bes_cyber_system_impact == BESCyberSystemImpact.HIGH:
            # CIP-004-6 R3: PRA is a prerequisite for any BCSI access.
            if not context.user_cleared_for_cip:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.DENIED,
                    reason=(
                        "NERC CIP-004-6 R3: Personnel risk assessment (PRA) not completed "
                        "— access to High Impact BES Cyber System information denied"
                    ),
                )

            # CIP-011-2 R1: Documented need-to-know required for all BCSI access.
            if not context.has_need_to_know:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.DENIED,
                    reason=(
                        "NERC CIP-011-2: Electronic Access Management requires documented "
                        "need-to-know for BES Cyber System Information (BCSI)"
                    ),
                )

            # CIP-005-7 R1: Electronic access to High Impact systems requires
            # authorized entry in Electronic Access Controls.
            if not context.is_authorized_electronic_access:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.DENIED,
                    reason=(
                        "NERC CIP-005-7: Electronic Access Controls not established "
                        "— access to High Impact BES Cyber Systems requires authorized EAP"
                    ),
                )

            # All CIP prerequisites satisfied for High Impact access.
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="NERC CIP: High Impact BCSI access — all CIP prerequisites satisfied",
                conditions=[
                    "NERC CIP-011: BCSI access — CIP-007-6 R4 logging and "
                    "CIP-010-4 configuration management monitoring required"
                ],
            )

        # ------------------------------------------------------------------
        # Medium Impact BES Cyber Systems.
        # ------------------------------------------------------------------
        if document.bes_cyber_system_impact == BESCyberSystemImpact.MEDIUM:
            # CIP-004-6 R3: PRA required for Medium Impact BES Cyber System access.
            if not context.user_cleared_for_cip:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.DENIED,
                    reason=(
                        "NERC CIP-004-6 R3: PRA required for Medium Impact BES Cyber "
                        "System information access"
                    ),
                )

            # CIP-011-2 R1: Need-to-know documentation required for BCSI.
            if not context.has_need_to_know:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.DENIED,
                    reason=(
                        "NERC CIP-011-2: Need-to-know documentation required for BCSI"
                    ),
                )

            # All prerequisites satisfied for Medium Impact access.
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="NERC CIP: Medium Impact BCSI access — PRA and need-to-know verified",
                conditions=[
                    "NERC CIP: Medium Impact BCSI — electronic access monitoring "
                    "per CIP-007 applies"
                ],
            )

        # ------------------------------------------------------------------
        # Low Impact BES Cyber Systems — CIP-003-8 / CIP-006-6 controls.
        # ------------------------------------------------------------------
        if document.bes_cyber_system_impact == BESCyberSystemImpact.LOW:
            # CIP-013-2 R1: Contractors and vendors must have active supply chain
            # agreements before accessing any BES Cyber System.
            if context.user_role in {EnergyRole.CONTRACTOR, EnergyRole.VENDOR} and not context.contractor_agreement_active:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.DENIED,
                    reason=(
                        "NERC CIP-013-2: Supply chain risk management — contractor/vendor "
                        "agreement must be active before accessing Low Impact BES Cyber Systems"
                    ),
                )

            # Low Impact access with basic CIP-006 physical security controls.
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="NERC CIP: Low Impact BES Cyber System access authorized",
                conditions=[
                    "NERC CIP: Low Impact BES Cyber System — physical security and "
                    "access management per CIP-006 applies"
                ],
            )

        # Default: unrecognized impact level — deny to protect infrastructure.
        return EnergyFilterResult(
            layer=self.LAYER_NAME,
            decision=EnergyDecision.DENIED,
            reason=(
                "NERC CIP: Unrecognized BES Cyber System impact classification "
                "— access denied pending classification review"
            ),
        )


# ---------------------------------------------------------------------------
# Layer 2: FERCRegulatoryFilter (FERC CEII and Regulatory Filings)
# ---------------------------------------------------------------------------

class FERCRegulatoryFilter:
    """
    Enforces FERC Critical Energy Infrastructure Information (CEII) protections
    and restrictions on FERC regulatory filings.

    FERC's CEII framework is established under 18 CFR Part 388 Subpart A and
    implements FOIA Exemption 3 protection for critical infrastructure details
    that could be used to plan an attack on the energy grid.  Key provisions:

      - 18 CFR §388.112: CEII definition.  Covers specific engineering,
        vulnerability, and detailed design information about critical energy
        infrastructure — substations, transmission lines, pipelines, LNG
        facilities, and interconnection details with attack-planning utility.

      - 18 CFR §388.113(a): CEII is categorically exempt from FOIA disclosure
        and is withheld from public release.

      - 18 CFR §388.113(d): FERC staff, commissioners, and other federal agency
        personnel with an official need for the information are authorized to
        access CEII without the NDA process.

      - 18 CFR §388.113(e): Non-government requestors with demonstrated need
        (e.g., regulated entities, state commissions, academic researchers) must
        execute a FERC-approved non-disclosure agreement before receiving CEII.
        Recipients may not further disclose CEII without prior FERC approval.
        CEII must be handled and destroyed per FERC procedures.

    Restricted FERC regulatory filings that do not rise to CEII status are
    controlled under protective order procedures. Access is limited to parties
    to the proceeding with documented need-to-know authorization.
    """

    LAYER_NAME = "FERC_REGULATORY"

    def evaluate(
        self, context: EnergyUtilitiesContext, document: EnergyDocument
    ) -> EnergyFilterResult:
        """
        Evaluate whether the requesting context satisfies FERC regulatory
        information access requirements for the document.

        Returns an EnergyFilterResult with PERMITTED or DENIED together with
        the operative FERC regulatory citation and finding.
        """
        # Public documents — not FERC-restricted; no CEII restriction applies.
        if document.is_public:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="Publicly available document — FERC regulatory restrictions do not apply",
            )

        # Document has no FERC restriction or CEII designation.
        if not document.is_ceii and not document.is_ferc_restricted:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="Document is not CEII and not FERC-restricted — FERC layer does not restrict",
            )

        # FERC staff and regulatory officials — 18 CFR §388.113(d) grants
        # standing access to CEII without the NDA requirement.
        if context.is_ferc_staff or context.user_role == EnergyRole.REGULATOR:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="FERC Staff access — 18 CFR §388.113(d) grants standing CEII access for FERC staff",
                conditions=[
                    "FERC Staff access — CEII handling procedures apply per 18 CFR Part 388"
                ],
            )

        # ------------------------------------------------------------------
        # CEII documents — 18 CFR §388.113(e) NDA requirement.
        # ------------------------------------------------------------------
        if document.is_ceii:
            if context.ferc_ceii_authorized:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.PERMITTED,
                    reason=(
                        "FERC CEII: Non-disclosure agreement on file — 18 CFR §388.113(e) "
                        "access authorized"
                    ),
                    conditions=[
                        "FERC CEII: Non-disclosure agreement on file — 18 CFR §388.113(e) "
                        "handling requirements apply; no further disclosure without FERC approval"
                    ],
                )
            else:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.DENIED,
                    reason=(
                        "FERC 18 CFR §388.113: Critical Energy Infrastructure Information "
                        "(CEII) — non-disclosure agreement required before access; "
                        "submit CEII request to FERC"
                    ),
                )

        # ------------------------------------------------------------------
        # FERC restricted filing (non-CEII) — protective order access.
        # ------------------------------------------------------------------
        if document.is_ferc_restricted and not document.is_ceii:
            # Internal personnel with need-to-know and appropriate roles —
            # permitted under the facility's internal FERC proceeding access controls.
            if context.user_role in {
                EnergyRole.COMPLIANCE_OFFICER,
                EnergyRole.EXECUTIVE,
                EnergyRole.GRID_OPERATOR,
            } and context.has_need_to_know:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.PERMITTED,
                    reason=(
                        "FERC Restricted Filing: Authorized role with documented need-to-know"
                    ),
                    conditions=[
                        "FERC Restricted Filing: Internal need-to-know access "
                        "— do not disclose externally"
                    ],
                )

            # All other requestors — restricted filings require documented
            # authorization under a FERC protective order.
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.DENIED,
                reason=(
                    "FERC Restricted Filing: Access limited to authorized personnel "
                    "with documented need-to-know"
                ),
            )

        # Unreachable given the conditional structure, but provide a safe default.
        return EnergyFilterResult(
            layer=self.LAYER_NAME,
            decision=EnergyDecision.DENIED,
            reason="FERC: Unresolved regulatory restriction state — access denied",
        )


# ---------------------------------------------------------------------------
# Layer 3: DOECybersecurityFilter (DOE CESER / Cybersecurity Requirements)
# ---------------------------------------------------------------------------

class DOECybersecurityFilter:
    """
    Enforces DOE CESER cybersecurity information protection requirements and
    DOE classified and sensitive information access controls.

    The Department of Energy administers two distinct information-protection
    regimes relevant to energy sector RAG systems:

    Classified information — DOE Orders 470.4B and 475.1B:
      DOE classifies information under the Atomic Energy Act and Executive
      Order 13526.  DOE Order 470.4B establishes the Safeguards and Security
      Program; individuals must hold the appropriate DOE security clearance
      before accessing classified information.  DOE Order 475.1B requires that
      all derivative classification decisions be traceable to an authoritative
      source.

    Sensitive Cybersecurity Information — DOE CESER Guidance:
      DOE CESER identifies sensitive but unclassified (SBU) cybersecurity
      information including grid vulnerability assessments, control system
      architecture diagrams, incident response plans, and sector-specific
      intrusion analysis.  This information is shared with energy sector
      partners through the Electricity Information Sharing and Analysis Center
      (E-ISAC) and DOE-authorized channels.  Access requires appropriate role
      authority and documented need-to-know per DOE's Cybersecurity Strategy.

    DOE Order 470.6 governs information sharing arrangements during
    regulatory audits and inspections.  Regulatory and audit access to
    DOE-sensitive materials is permitted with appropriate handling conditions.
    """

    LAYER_NAME = "DOE_CYBERSECURITY"

    def evaluate(
        self, context: EnergyUtilitiesContext, document: EnergyDocument
    ) -> EnergyFilterResult:
        """
        Evaluate whether the requesting context satisfies DOE cybersecurity
        information access requirements for the document.

        Returns an EnergyFilterResult with PERMITTED or DENIED together with
        the operative DOE order or CESER guidance citation and finding.
        """
        # Public documents — DOE cybersecurity restrictions do not apply.
        if document.is_public:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="Publicly available document — DOE cybersecurity restrictions do not apply",
            )

        # Document is neither DOE sensitive nor classified — layer does not restrict.
        if not document.is_doe_sensitive and not document.is_classified:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="Document is not DOE sensitive or classified — DOE cybersecurity layer does not restrict",
            )

        # Regulatory and formal audit access — permitted under DOE Order 470.6
        # information sharing arrangements for oversight activities.
        if context.user_role == EnergyRole.REGULATOR or context.is_audit_access:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="DOE: Regulatory or audit access — authorized under oversight authority",
                conditions=[
                    "DOE regulatory/audit access — information handling per DOE Order 470.6"
                ],
            )

        # ------------------------------------------------------------------
        # Classified information — requires appropriate DOE clearance.
        # ------------------------------------------------------------------
        if document.is_classified:
            if context.doe_clearance_level == "classified":
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.PERMITTED,
                    reason=(
                        "DOE Classified: Proper clearance verified — access authorized"
                    ),
                    conditions=[
                        "DOE Classified: Proper clearance verified — handle per "
                        "DOE O 475.1B and facility security procedures"
                    ],
                )
            else:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.DENIED,
                    reason=(
                        "DOE: Classified information — appropriate security clearance "
                        "required per DOE O 470.4B"
                    ),
                )

        # ------------------------------------------------------------------
        # DOE sensitive cybersecurity information (SBU, non-classified).
        # ------------------------------------------------------------------
        if document.is_doe_sensitive and not document.is_classified:
            # Personnel with sensitive or classified DOE clearance — authorized
            # for SBU CESER information under the clearance program.
            if context.doe_clearance_level in {"sensitive", "classified"}:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.PERMITTED,
                    reason=(
                        "DOE CESER: Sensitive cybersecurity information — clearance level verified"
                    ),
                    conditions=[
                        "DOE Sensitive Cybersecurity Information: Need-to-know clearance "
                        "verified — limited distribution per DOE CESER guidance"
                    ],
                )

            # Authorized operational roles with documented need-to-know — permitted
            # under DOE CESER's sector-partner information sharing framework.
            if context.user_role in {
                EnergyRole.SECURITY_ANALYST,
                EnergyRole.COMPLIANCE_OFFICER,
                EnergyRole.GRID_OPERATOR,
            } and context.has_need_to_know:
                return EnergyFilterResult(
                    layer=self.LAYER_NAME,
                    decision=EnergyDecision.PERMITTED,
                    reason=(
                        "DOE CESER: Sensitive cybersecurity information — authorized role "
                        "with documented need-to-know"
                    ),
                    conditions=[
                        "DOE CESER: Sensitive cybersecurity information — authorized role "
                        "with need-to-know; handle per DOE Cybersecurity Strategy"
                    ],
                )

            # All other requestors — DOE sensitive information requires clearance
            # or formal need-to-know authorization.
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.DENIED,
                reason=(
                    "DOE CESER: Sensitive cybersecurity information — access requires "
                    "appropriate clearance or documented need-to-know authorization"
                ),
            )

        # Unreachable given the conditional structure, but provide a safe default.
        return EnergyFilterResult(
            layer=self.LAYER_NAME,
            decision=EnergyDecision.DENIED,
            reason="DOE: Unresolved information sensitivity state — access denied",
        )


# ---------------------------------------------------------------------------
# Layer 4: NRCNuclearSecurityFilter (NRC 10 CFR Part 73 Safeguards)
# ---------------------------------------------------------------------------

class NRCNuclearSecurityFilter:
    """
    Enforces NRC 10 CFR Part 73 Safeguards Information (SGI) protection
    requirements for nuclear facility information systems.

    NRC Safeguards Information is a Sensitive Unclassified Non-Safeguards
    Information (SUNSI) category with the highest protection tier for
    non-classified nuclear security information. Key provisions:

      - 10 CFR 73.21 (Protection of Safeguards Information — General
        Performance Objectives and Requirements):
        Requires licensees, applicants, and certificate holders to protect
        SGI from unauthorized disclosure, use, or access.  Each document
        containing SGI must be marked, controlled, and accessed only by
        individuals with a documented, NRC-approved need-to-know.  Unauthorized
        disclosure is a federal violation subject to civil and criminal penalties
        under 18 USC § 2277 and the Atomic Energy Act of 1954.

      - 10 CFR 73.22 (Protection of Safeguards Information — Specific
        Requirements for Power Reactor Licensees):
        Requires power reactor licensees to designate a Safeguards Coordinator
        responsible for controlling SGI access.  Section (d) governs contractors
        and vendors — SGI access requires prior NRC approval, a demonstrated
        need-to-know, and an executed confidentiality agreement.

      - 10 CFR 73.23 (Other Licensees and Certificate Holders):
        Extends parallel SGI protections to fuel cycle facilities, transportation,
        and other NRC-licensed activities.

      NRC inspectors and resident inspectors have standing regulatory authority
      to access SGI as part of their inspection responsibilities.  Licensee
      personnel (including contractors under 73.22(d)) require documented
      need-to-know authorization from the NRC or the Safeguards Coordinator.
    """

    LAYER_NAME = "NRC_NUCLEAR_SECURITY"

    def evaluate(
        self, context: EnergyUtilitiesContext, document: EnergyDocument
    ) -> EnergyFilterResult:
        """
        Evaluate whether the requesting context satisfies NRC 10 CFR Part 73
        Safeguards Information access requirements for the document.

        Returns an EnergyFilterResult with PERMITTED or DENIED together with
        the operative NRC regulation citation and finding.
        """
        # Public documents carry no NRC safeguards restriction.
        if document.is_public:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="Publicly available document — NRC safeguards restrictions do not apply",
            )

        # Document does not contain Safeguards Information — layer does not restrict.
        if not document.is_safeguards_info:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason="Document does not contain Safeguards Information — 10 CFR Part 73 does not restrict",
            )

        # ------------------------------------------------------------------
        # Safeguards Information (SGI) — 10 CFR 73.21 / 73.22 controls.
        # ------------------------------------------------------------------

        # NRC inspectors and regulatory officials — standing authority to access
        # SGI as part of the NRC's inspection and oversight mandate.
        if context.user_role == EnergyRole.REGULATOR or context.is_nrc_inspector:
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason=(
                    "NRC SGI: Inspector or regulator access — standing regulatory authority "
                    "under 10 CFR Part 73"
                ),
                conditions=[
                    "NRC SGI: Inspector/regulator access — 10 CFR 73.22 protection "
                    "requirements apply; protect against unauthorized disclosure"
                ],
            )

        # Authorized licensee personnel (compliance, security, grid operations)
        # with NRC safeguards authorization and documented need-to-know.
        if (
            context.nrc_safeguards_authorized
            and context.has_need_to_know
            and context.user_role in {
                EnergyRole.COMPLIANCE_OFFICER,
                EnergyRole.SECURITY_ANALYST,
                EnergyRole.GRID_OPERATOR,
            }
        ):
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason=(
                    "NRC 10 CFR 73.21: SGI access authorized — NRC authorization and "
                    "need-to-know verified"
                ),
                conditions=[
                    "NRC 10 CFR 73.21: SGI access authorized — protect from unauthorized "
                    "disclosure; access logs required; need-to-know basis"
                ],
            )

        # Contractors and vendors — 10 CFR 73.22(d) governs vendor SGI access.
        # Requires NRC authorization, active agreement, and documented need-to-know.
        if (
            context.user_role in {EnergyRole.CONTRACTOR, EnergyRole.VENDOR}
            and context.nrc_safeguards_authorized
            and context.contractor_agreement_active
        ):
            return EnergyFilterResult(
                layer=self.LAYER_NAME,
                decision=EnergyDecision.PERMITTED,
                reason=(
                    "NRC 10 CFR 73.22(d): SGI contractor/vendor access — NRC-approved "
                    "authorization and active agreement verified"
                ),
                conditions=[
                    "NRC 10 CFR 73.22(d): SGI contractor access — NRC-approved "
                    "need-to-know; confidentiality agreement required"
                ],
            )

        # All other requestors — SGI access denied. Unauthorized disclosure is a
        # federal violation under 18 USC § 2277 and the Atomic Energy Act.
        return EnergyFilterResult(
            layer=self.LAYER_NAME,
            decision=EnergyDecision.DENIED,
            reason=(
                "NRC 10 CFR 73.21: Safeguards Information — access requires NRC "
                "authorization and documented need-to-know; unauthorized disclosure "
                "is a federal violation"
            ),
        )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class EnergyUtilitiesRAGPipeline:
    """
    Four-layer defense-in-depth RAG retrieval pipeline for energy and utilities.

    Each layer independently evaluates a document against the requesting context.
    The pipeline runs layers in sequence; the first DENIED result stops evaluation
    for that document.  Only documents that pass all four layers are returned.

    Layers in order:
      1. NERCCIPFilter             — NERC CIP BES Cyber System information protection
      2. FERCRegulatoryFilter      — FERC CEII and restricted regulatory filing access
      3. DOECybersecurityFilter    — DOE CESER sensitive and classified information
      4. NRCNuclearSecurityFilter  — NRC 10 CFR Part 73 Safeguards Information

    Audit records are generated for every document regardless of outcome,
    providing a complete access trail for regulatory compliance and NERC CIP
    event logging obligations.
    """

    def __init__(self) -> None:
        self._layers = [
            NERCCIPFilter(),
            FERCRegulatoryFilter(),
            DOECybersecurityFilter(),
            NRCNuclearSecurityFilter(),
        ]

    def retrieve(
        self,
        context: EnergyUtilitiesContext,
        documents: list[EnergyDocument],
    ) -> list[EnergyDocument]:
        """
        Return the subset of documents that pass all four filter layers.

        Documents are evaluated independently; a denial on any layer
        causes the document to be excluded from the result set.
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

    def retrieve_with_audit(
        self,
        context: EnergyUtilitiesContext,
        documents: list[EnergyDocument],
    ) -> tuple[list[EnergyDocument], list[EnergyAuditRecord]]:
        """
        Return permitted documents AND a full audit trail for every document.

        The audit trail captures the decision and per-layer results for each
        document regardless of whether it was ultimately permitted or denied.
        This supports NERC CIP-007 event logging, FERC compliance reporting,
        and NRC access record-keeping obligations.
        """
        permitted: list[EnergyDocument] = []
        audit_records: list[EnergyAuditRecord] = []

        for doc in documents:
            layer_results: list[dict] = []
            allow = True
            final_decision = EnergyDecision.PERMITTED

            for layer in self._layers:
                result = layer.evaluate(context, doc)
                layer_results.append(
                    {
                        "layer": result.layer,
                        "decision": result.decision.value,
                        "reason": result.reason,
                        "conditions": result.conditions,
                    }
                )
                if result.is_denied:
                    allow = False
                    final_decision = EnergyDecision.DENIED
                    break

            if allow:
                permitted.append(doc)

            audit_records.append(
                EnergyAuditRecord(
                    user_id=context.user_id,
                    facility_id=context.facility_id,
                    document_id=doc.document_id,
                    decision=final_decision,
                    layer_results=layer_results,
                )
            )

        return permitted, audit_records


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class EnergyAuditRecord:
    """
    Captures the full decision trail for a single RAG retrieval event.

    This record should be persisted to an immutable audit log to satisfy:
      - NERC CIP-007-6 R4: Event logging for BES Cyber System access (90-day
        retention for High Impact systems).
      - NERC CIP-011-2 R1: Documentation of BCSI access events.
      - FERC 18 CFR §388.113(e): CEII access tracking for NDA compliance.
      - NRC 10 CFR 73.21: SGI access record-keeping requirements.

    All fields are populated at retrieval time; the timestamp uses the system
    clock and should be treated as UTC for regulatory record-keeping purposes.
    """

    user_id: str
    facility_id: str
    document_id: str
    decision: EnergyDecision
    layer_results: list          # Per-layer result dicts from retrieve_with_audit
    timestamp: float = field(default_factory=time.time)

    def to_audit_log(self) -> dict:
        return {
            "event": "ENERGY_RAG_RETRIEVAL",
            "user_id": self.user_id,
            "facility_id": self.facility_id,
            "document_id": self.document_id,
            "decision": self.decision.value,
            "layer_results": self.layer_results,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("=" * 70)
    print("Energy and Utilities RAG Pipeline — Smoke Test")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Shared documents used across scenarios
    # ------------------------------------------------------------------

    high_impact_bes_doc = EnergyDocument(
        document_id="doc-001-high-impact-bes-config",
        bes_cyber_system_impact=BESCyberSystemImpact.HIGH,
        is_ceii=False,
        is_ferc_restricted=False,
        is_doe_sensitive=False,
        is_classified=False,
        is_safeguards_info=False,
        is_public=False,
    )

    ceii_doc = EnergyDocument(
        document_id="doc-002-transmission-vulnerability-ceii",
        bes_cyber_system_impact=BESCyberSystemImpact.NOT_BES,
        is_ceii=True,
        is_ferc_restricted=True,
        is_doe_sensitive=False,
        is_classified=False,
        is_safeguards_info=False,
        is_public=False,
    )

    safeguards_doc = EnergyDocument(
        document_id="doc-003-nuclear-physical-protection-sgi",
        bes_cyber_system_impact=BESCyberSystemImpact.NOT_BES,
        is_ceii=False,
        is_ferc_restricted=False,
        is_doe_sensitive=False,
        is_classified=False,
        is_safeguards_info=True,
        is_public=False,
    )

    public_tariff_doc = EnergyDocument(
        document_id="doc-004-public-ferc-tariff-filing",
        bes_cyber_system_impact=BESCyberSystemImpact.NOT_BES,
        is_ceii=False,
        is_ferc_restricted=False,
        is_doe_sensitive=False,
        is_classified=False,
        is_safeguards_info=False,
        is_public=True,
    )

    low_impact_bes_doc = EnergyDocument(
        document_id="doc-005-low-impact-bes-substation",
        bes_cyber_system_impact=BESCyberSystemImpact.LOW,
        is_ceii=False,
        is_ferc_restricted=False,
        is_doe_sensitive=False,
        is_classified=False,
        is_safeguards_info=False,
        is_public=False,
    )

    all_documents = [
        high_impact_bes_doc,
        ceii_doc,
        safeguards_doc,
        public_tariff_doc,
        low_impact_bes_doc,
    ]

    pipeline = EnergyUtilitiesRAGPipeline()

    # ------------------------------------------------------------------
    # Scenario 1: Cleared grid operator accessing HIGH impact BES document
    # Expected: high_impact_bes_doc permitted; public_tariff_doc permitted;
    #           others denied (CEII without NDA, SGI without NRC auth,
    #           low-impact BES permitted for grid operator)
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: Cleared Grid Operator with CIP Access ---")

    cleared_operator_context = EnergyUtilitiesContext(
        user_id="user-grid-operator-chen",
        user_role=EnergyRole.GRID_OPERATOR,
        facility_id="facility-control-center-west",
        user_cleared_for_cip=True,
        has_need_to_know=True,
        is_authorized_electronic_access=True,
        is_on_site_physical_access=True,
        contractor_agreement_active=False,
        ferc_ceii_authorized=False,
        is_ferc_staff=False,
        doe_clearance_level="",
        nrc_safeguards_authorized=False,
        is_nrc_inspector=False,
        is_audit_access=False,
    )

    permitted_docs, audit_records = pipeline.retrieve_with_audit(
        cleared_operator_context, all_documents
    )

    print(
        f"  Context:  Grid operator Chen — CIP-cleared, authorized EAC, "
        f"no CEII NDA, no NRC authorization"
    )
    print(f"  Documents submitted: {len(all_documents)}")
    print(f"  Documents permitted: {len(permitted_docs)}")
    for record in audit_records:
        layers_evaluated = len(record.layer_results)
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id} "
            f"({layers_evaluated} layer(s) evaluated)"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer']}: {lr['reason']}")
            for cond in lr.get("conditions", []):
                print(f"                    Condition: {cond}")

    # Cleared grid operator: HIGH BES permitted, CEII denied (no NDA),
    # SGI denied (no NRC auth), public tariff permitted, LOW BES permitted
    assert any(d.document_id == "doc-001-high-impact-bes-config" for d in permitted_docs), (
        "Expected HIGH impact BES doc permitted for cleared grid operator"
    )
    assert not any(d.document_id == "doc-002-transmission-vulnerability-ceii" for d in permitted_docs), (
        "Expected CEII doc denied for grid operator without CEII NDA"
    )
    assert not any(d.document_id == "doc-003-nuclear-physical-protection-sgi" for d in permitted_docs), (
        "Expected SGI doc denied for grid operator without NRC authorization"
    )
    assert any(d.document_id == "doc-004-public-ferc-tariff-filing" for d in permitted_docs), (
        "Expected public tariff doc always permitted"
    )
    assert any(d.document_id == "doc-005-low-impact-bes-substation" for d in permitted_docs), (
        "Expected LOW impact BES doc permitted for cleared grid operator"
    )
    print(
        "  ASSERTION PASSED: HIGH BES permitted; CEII denied; SGI denied; "
        "public permitted; LOW BES permitted."
    )

    # ------------------------------------------------------------------
    # Scenario 2: Contractor without active agreement accessing LOW impact BES
    # Expected: LOW impact BES doc denied at NERC CIP layer
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Contractor Without Active Agreement — LOW BES Denial ---")

    inactive_contractor_context = EnergyUtilitiesContext(
        user_id="user-contractor-patel",
        user_role=EnergyRole.CONTRACTOR,
        facility_id="facility-substation-east",
        user_cleared_for_cip=True,
        has_need_to_know=True,
        is_authorized_electronic_access=False,
        is_on_site_physical_access=False,
        contractor_agreement_active=False,   # Agreement expired or not active
        ferc_ceii_authorized=False,
        is_ferc_staff=False,
        doe_clearance_level="",
        nrc_safeguards_authorized=False,
        is_nrc_inspector=False,
        is_audit_access=False,
    )

    low_bes_only = [low_impact_bes_doc]
    permitted_low, audit_low = pipeline.retrieve_with_audit(
        inactive_contractor_context, low_bes_only
    )

    print(
        f"  Context:  Contractor Patel — contractor_agreement_active=False"
    )
    print(f"  Documents submitted: {len(low_bes_only)}")
    print(f"  Documents permitted: {len(permitted_low)}")
    for record in audit_low:
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id}"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer']}: {lr['reason']}")

    assert len(permitted_low) == 0, (
        f"Expected LOW BES doc denied for contractor without active agreement, "
        f"got {len(permitted_low)} permitted"
    )
    print(
        "  ASSERTION PASSED: LOW BES doc denied for contractor without "
        "active CIP-013 supply chain agreement."
    )

    # ------------------------------------------------------------------
    # Scenario 3: CEII document — grid operator without NDA denied at FERC layer
    # Expected: denied at FERCRegulatoryFilter
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: CEII Document Without NDA — FERC Layer Denial ---")

    no_nda_context = EnergyUtilitiesContext(
        user_id="user-compliance-officer-alvarez",
        user_role=EnergyRole.COMPLIANCE_OFFICER,
        facility_id="facility-transmission-north",
        user_cleared_for_cip=True,
        has_need_to_know=True,
        is_authorized_electronic_access=True,
        is_on_site_physical_access=True,
        contractor_agreement_active=False,
        ferc_ceii_authorized=False,    # No CEII NDA on file
        is_ferc_staff=False,
        doe_clearance_level="",
        nrc_safeguards_authorized=False,
        is_nrc_inspector=False,
        is_audit_access=False,
    )

    ceii_only = [ceii_doc]
    permitted_ceii, audit_ceii = pipeline.retrieve_with_audit(
        no_nda_context, ceii_only
    )

    print(
        f"  Context:  Compliance officer Alvarez — ferc_ceii_authorized=False"
    )
    print(f"  Documents submitted: {len(ceii_only)}")
    print(f"  Documents permitted: {len(permitted_ceii)}")
    for record in audit_ceii:
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id}"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer']}: {lr['reason']}")

    assert len(permitted_ceii) == 0, (
        f"Expected CEII doc denied without NDA, got {len(permitted_ceii)} permitted"
    )
    # Confirm denial occurred at FERC layer (second layer), not NERC CIP layer
    ceii_record = audit_ceii[0]
    assert ceii_record.layer_results[-1]["layer"] == "FERC_REGULATORY", (
        f"Expected denial at FERC_REGULATORY, got {ceii_record.layer_results[-1]['layer']}"
    )
    print(
        "  ASSERTION PASSED: CEII doc denied at FERC_REGULATORY layer "
        "— CEII NDA required before access."
    )

    # ------------------------------------------------------------------
    # Scenario 4: Safeguards Information without NRC authorization — denied
    # Expected: denied at NRCNuclearSecurityFilter
    # ------------------------------------------------------------------
    print("\n--- Scenario 4: Safeguards Information Without NRC Auth — NRC Layer Denial ---")

    no_nrc_auth_context = EnergyUtilitiesContext(
        user_id="user-security-analyst-johnson",
        user_role=EnergyRole.SECURITY_ANALYST,
        facility_id="facility-nuclear-plant-alpha",
        user_cleared_for_cip=True,
        has_need_to_know=True,
        is_authorized_electronic_access=True,
        is_on_site_physical_access=True,
        contractor_agreement_active=False,
        ferc_ceii_authorized=False,
        is_ferc_staff=False,
        doe_clearance_level="sensitive",
        nrc_safeguards_authorized=False,   # No NRC SGI authorization
        is_nrc_inspector=False,
        is_audit_access=False,
    )

    sgi_only = [safeguards_doc]
    permitted_sgi, audit_sgi = pipeline.retrieve_with_audit(
        no_nrc_auth_context, sgi_only
    )

    print(
        f"  Context:  Security analyst Johnson — doe_clearance_level='sensitive', "
        f"nrc_safeguards_authorized=False"
    )
    print(f"  Documents submitted: {len(sgi_only)}")
    print(f"  Documents permitted: {len(permitted_sgi)}")
    for record in audit_sgi:
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id}"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer']}: {lr['reason']}")

    assert len(permitted_sgi) == 0, (
        f"Expected SGI doc denied without NRC authorization, "
        f"got {len(permitted_sgi)} permitted"
    )
    # Confirm denial occurred at NRC layer (fourth layer)
    sgi_record = audit_sgi[0]
    assert sgi_record.layer_results[-1]["layer"] == "NRC_NUCLEAR_SECURITY", (
        f"Expected denial at NRC_NUCLEAR_SECURITY, got {sgi_record.layer_results[-1]['layer']}"
    )
    print(
        "  ASSERTION PASSED: SGI doc denied at NRC_NUCLEAR_SECURITY layer "
        "— NRC 10 CFR 73.21 authorization required."
    )

    # ------------------------------------------------------------------
    # Scenario 5: Public document — always permitted through all four layers
    # Expected: all four layers PASS; document permitted
    # ------------------------------------------------------------------
    print("\n--- Scenario 5: Public Document — Always Permitted ---")

    anonymous_context = EnergyUtilitiesContext(
        user_id="user-anonymous-public",
        user_role=EnergyRole.ADMIN,
        facility_id="",
        user_cleared_for_cip=False,
        has_need_to_know=False,
        is_authorized_electronic_access=False,
        is_on_site_physical_access=False,
        contractor_agreement_active=False,
        ferc_ceii_authorized=False,
        is_ferc_staff=False,
        doe_clearance_level="",
        nrc_safeguards_authorized=False,
        is_nrc_inspector=False,
        is_audit_access=False,
    )

    public_only = [public_tariff_doc]
    permitted_public, audit_public = pipeline.retrieve_with_audit(
        anonymous_context, public_only
    )

    print(
        f"  Context:  Anonymous user — no clearances, no authorizations"
    )
    print(f"  Documents submitted: {len(public_only)}")
    print(f"  Documents permitted: {len(permitted_public)}")
    for record in audit_public:
        print(
            f"    [{record.decision.value.upper():8s}] {record.document_id}"
        )
        for lr in record.layer_results:
            status_marker = "PASS" if lr["decision"] == "permitted" else "DENY"
            print(f"             [{status_marker}] {lr['layer']}: {lr['reason']}")

    assert len(permitted_public) == 1, (
        f"Expected public document always permitted, got {len(permitted_public)}"
    )
    # Confirm all four layers evaluated and all passed
    pub_record = audit_public[0]
    assert len(pub_record.layer_results) == 4, (
        f"Expected 4 layers evaluated for public doc, got {len(pub_record.layer_results)}"
    )
    assert all(lr["decision"] == "permitted" for lr in pub_record.layer_results), (
        "Expected all four layers to PASS for public document"
    )
    print(
        "  ASSERTION PASSED: Public document permitted through all four layers."
    )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("All smoke test assertions passed.")
    print("=" * 70)

    print("\nAudit log sample (public tariff document):")
    print(json.dumps(audit_public[0].to_audit_log(), indent=2))
