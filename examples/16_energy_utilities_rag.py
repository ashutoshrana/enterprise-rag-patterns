"""
16_energy_utilities_rag.py — CEII + NERC CIP + NRC SUNSI compliance
for an energy utility grid operations knowledge base assistant.

Demonstrates defense-in-depth RAG retrieval for a bulk electric system
(BES) operator where three distinct regulatory compliance obligations apply
simultaneously:

    Layer 1  — CEII (FERC 18 CFR Part 388.113): Critical Energy Infrastructure
               Information is subject to FERC-mandated access controls. Only
               personnel with FERC-granted CEII designation or utility-authorized
               CEII access may retrieve documents tagged with CEII categories.
               CEIIFilter enforces the CEII boundary before documents reach the
               LLM context window.

    Layer 2  — NERC CIP (CIP-004-7 / CIP-011-3): BES Cyber System Information
               (BCSI) requires access controls under NERC Reliability Standards.
               CIP-004-7 requires personnel to have completed cybersecurity
               awareness training before accessing BCSI. CIP-011-3 requires
               information protection controls for BCSI at rest and in transit.
               NERCCIPFilter enforces CIP tier and training compliance.

    Layer 3  — NRC SUNSI (10 CFR Part 2.390): Sensitive Unclassified
               Non-Safeguards Information at nuclear generation facilities is
               subject to NRC access controls. SUNSIFilter blocks nuclear
               safeguards information from non-NRC-authorized personnel.

Scenarios
---------

  A. Certified system operator queries grid topology and interconnection docs:
     CEII passes (authorized), NERC CIP passes (CIP-tier 3 trained), NRC SUNSI
     blocks nuclear safeguards docs → mixed retrieval (topology returned, safeguards
     blocked).

  B. Third-party contractor (NERC CIP personnel access not yet completed):
     NERC CIP CIP-004 blocks BCSI documents until training attestation on file.
     Non-BCSI public grid information returned.

  C. CEII query without FERC-authorized role:
     CEIIFilter blocks all CEII-tagged critical infrastructure documents.
     Public capacity and interconnection queue data (non-CEII) returned.

  D. Public information query (grid pricing, interconnection queue):
     All three layers pass — no CEII, no BCSI, no SUNSI. Full retrieval.

No external dependencies required.

Run:
    python examples/16_energy_utilities_rag.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------

class CEIICategory(str, Enum):
    """FERC CEII categories (18 CFR Part 388.113)."""
    CRITICAL_ASSET_LOCATION = "CEII//CRITICAL_ASSET"
    GRID_VULNERABILITY = "CEII//VULNERABILITY"
    PROTECTION_SYSTEM = "CEII//PROTECTION_SYSTEM"
    CONTROL_SYSTEM = "CEII//CONTROL_SYSTEM"
    CAPACITY_SENSITIVE = "CEII//CAPACITY_SENSITIVE"
    NON_CEII = "NON-CEII"
    PUBLIC = "PUBLIC"


class NERCCIPTier(str, Enum):
    """NERC CIP reliability standard tiers for BES Cyber Systems."""
    HIGH_IMPACT = "CIP_HIGH"       # Transmission stations ≥ 500kV, control centers
    MEDIUM_IMPACT = "CIP_MEDIUM"   # Transmission substations ≥ 200kV, generation ≥ 1500 MW
    LOW_IMPACT = "CIP_LOW"         # Distribution-level systems, small generation
    NOT_APPLICABLE = "CIP_NA"      # Non-BES systems, public information


class OperatorRole(str, Enum):
    """Electric utility operational roles."""
    SYSTEM_OPERATOR = "system_operator"             # BA/TO system operators
    CIP_COMPLIANCE_ANALYST = "cip_compliance"       # NERC CIP audit/compliance staff
    FIELD_ENGINEER = "field_engineer"               # Substation/field maintenance
    THIRD_PARTY_CONTRACTOR = "contractor"           # Vendors, EPC contractors
    EXECUTIVE = "executive"                         # Corporate officers
    NRC_AUTHORIZED = "nrc_authorized"               # Nuclear plant personnel (NRC-cleared)
    PUBLIC = "public"                               # Public information requests


class SUNSIType(str, Enum):
    """NRC Sensitive Unclassified Non-Safeguards Information types (10 CFR Part 2.390)."""
    SAFEGUARDS_INFORMATION = "SGI"          # Nuclear material quantities, security plans
    SECURITY_RELATED_INFO = "SRI"           # Physical protection systems
    EXPORT_CONTROLLED = "EXPORT_CTRL"       # Nuclear technology export controls
    NON_SUNSI = "NON_SUNSI"


# ---------------------------------------------------------------------------
# Access context
# ---------------------------------------------------------------------------

@dataclass
class EnergyAccessContext:
    """Access boundary for a single retrieval session at a utility operator."""
    user_id: str
    operator_role: OperatorRole
    authorized_ceii_categories: frozenset[CEIICategory] = field(default_factory=frozenset)
    nerc_cip_training_complete: bool = False
    nerc_cip_authorized_tiers: frozenset[NERCCIPTier] = field(default_factory=frozenset)
    nrc_sunsi_authorized: bool = False

    def may_access_ceii(self, category: CEIICategory) -> bool:
        if category in (CEIICategory.NON_CEII, CEIICategory.PUBLIC):
            return True
        return category in self.authorized_ceii_categories

    def may_access_bcsi(self, tier: NERCCIPTier) -> bool:
        if tier in (NERCCIPTier.NOT_APPLICABLE,):
            return True
        if not self.nerc_cip_training_complete:
            return False
        return tier in self.nerc_cip_authorized_tiers

    def may_access_sunsi(self, sunsi_type: SUNSIType) -> bool:
        if sunsi_type == SUNSIType.NON_SUNSI:
            return True
        return self.nrc_sunsi_authorized


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class EnergyComplianceAuditRecord:
    """Per-query audit record for FERC/NERC/NRC compliance."""
    query_id: str
    user_id: str
    operator_role: str
    total_candidates: int = 0
    ceii_blocked: list[str] = field(default_factory=list)
    nerc_cip_blocked: list[str] = field(default_factory=list)
    nrc_sunsi_blocked: list[str] = field(default_factory=list)
    documents_returned: list[str] = field(default_factory=list)
    applicable_regulations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.applicable_regulations = [
            "FERC 18 CFR Part 388.113 (CEII)",
            "NERC CIP-004-7 (Personnel & Training)",
            "NERC CIP-011-3 (Information Protection)",
            "NRC 10 CFR Part 2.390 (SUNSI)",
        ]

    @property
    def total_blocked(self) -> int:
        blocked = set(self.ceii_blocked) | set(self.nerc_cip_blocked) | set(self.nrc_sunsi_blocked)
        return len(blocked)


# ---------------------------------------------------------------------------
# Layer 1 — CEII Filter (FERC 18 CFR Part 388.113)
# ---------------------------------------------------------------------------

class CEIIFilter:
    """
    Enforces FERC Critical Energy Infrastructure Information access controls.

    Documents tagged with CEII categories may only be retrieved by users with
    explicit FERC CEII authorization for that category. CEII includes:
    - Critical asset physical locations and GPS coordinates
    - Grid vulnerability assessments
    - Protection system configurations
    - Control system architectures and SCADA topologies
    - Sensitive capacity and generation data
    """

    def filter(
        self,
        documents: list[dict],
        context: EnergyAccessContext,
        audit: EnergyComplianceAuditRecord,
    ) -> list[dict]:
        passed: list[dict] = []
        for doc in documents:
            ceii_category_str = doc.get("ceii_category", CEIICategory.NON_CEII.value)
            try:
                ceii_category = CEIICategory(ceii_category_str)
            except ValueError:
                ceii_category = CEIICategory.NON_CEII

            if context.may_access_ceii(ceii_category):
                passed.append(doc)
            else:
                audit.ceii_blocked.append(doc["id"])

        return passed


# ---------------------------------------------------------------------------
# Layer 2 — NERC CIP Filter (CIP-004-7 + CIP-011-3)
# ---------------------------------------------------------------------------

class NERCCIPFilter:
    """
    Enforces NERC CIP cybersecurity standards for BES Cyber System Information.

    CIP-004-7: Personnel with access to BES Cyber Systems must have completed
    cybersecurity awareness training and have documented access authorization.

    CIP-011-3: BES Cyber System Information (BCSI) must be protected against
    unauthorized access. Only personnel with documented need-to-know and
    completed training may access BCSI.
    """

    def filter(
        self,
        documents: list[dict],
        context: EnergyAccessContext,
        audit: EnergyComplianceAuditRecord,
    ) -> list[dict]:
        passed: list[dict] = []
        for doc in documents:
            cip_tier_str = doc.get("nerc_cip_tier", NERCCIPTier.NOT_APPLICABLE.value)
            try:
                cip_tier = NERCCIPTier(cip_tier_str)
            except ValueError:
                cip_tier = NERCCIPTier.NOT_APPLICABLE

            if context.may_access_bcsi(cip_tier):
                passed.append(doc)
            else:
                audit.nerc_cip_blocked.append(doc["id"])

        return passed


# ---------------------------------------------------------------------------
# Layer 3 — NRC SUNSI Filter (10 CFR Part 2.390)
# ---------------------------------------------------------------------------

class SUNSIFilter:
    """
    Enforces NRC Sensitive Unclassified Non-Safeguards Information controls.

    10 CFR Part 2.390 governs public availability of NRC documents. Certain
    categories — safeguards information, physical protection systems, export-
    controlled nuclear technology — may only be accessed by NRC-authorized
    personnel or specifically designated licensees.
    """

    def filter(
        self,
        documents: list[dict],
        context: EnergyAccessContext,
        audit: EnergyComplianceAuditRecord,
    ) -> list[dict]:
        passed: list[dict] = []
        for doc in documents:
            sunsi_type_str = doc.get("sunsi_type", SUNSIType.NON_SUNSI.value)
            try:
                sunsi_type = SUNSIType(sunsi_type_str)
            except ValueError:
                sunsi_type = SUNSIType.NON_SUNSI

            if context.may_access_sunsi(sunsi_type):
                passed.append(doc)
            else:
                audit.nrc_sunsi_blocked.append(doc["id"])

        return passed


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

class EnergyRAGPipeline:
    """Three-layer defense-in-depth RAG pipeline for energy utility operators."""

    def __init__(self) -> None:
        self._ceii_filter = CEIIFilter()
        self._cip_filter = NERCCIPFilter()
        self._sunsi_filter = SUNSIFilter()

    def retrieve(
        self,
        query: str,
        candidates: list[dict],
        context: EnergyAccessContext,
    ) -> tuple[list[dict], EnergyComplianceAuditRecord]:
        audit = EnergyComplianceAuditRecord(
            query_id=str(uuid.uuid4()),
            user_id=context.user_id,
            operator_role=context.operator_role.value,
            total_candidates=len(candidates),
        )

        # Layer 1: CEII
        after_ceii = self._ceii_filter.filter(candidates, context, audit)
        # Layer 2: NERC CIP
        after_cip = self._cip_filter.filter(after_ceii, context, audit)
        # Layer 3: NRC SUNSI
        after_sunsi = self._sunsi_filter.filter(after_cip, context, audit)

        audit.documents_returned = [doc["id"] for doc in after_sunsi]
        return after_sunsi, audit


# ---------------------------------------------------------------------------
# Scenario helpers
# ---------------------------------------------------------------------------

def _print_scenario(label: str, description: str, query: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"Scenario {label}: {description}")
    print(f"Query: {query}")
    print("=" * 70)


def _print_result(docs: list[dict], audit: EnergyComplianceAuditRecord) -> None:
    print(f"Documents returned ({len(docs)}):")
    for d in docs:
        print(f"  + [{d.get('ceii_category','?')} / {d.get('nerc_cip_tier','?')}] {d['title']}")
    if audit.ceii_blocked:
        print(f"CEII blocked ({len(audit.ceii_blocked)}): {audit.ceii_blocked}")
    if audit.nerc_cip_blocked:
        print(f"NERC CIP blocked ({len(audit.nerc_cip_blocked)}): {audit.nerc_cip_blocked}")
    if audit.nrc_sunsi_blocked:
        print(f"NRC SUNSI blocked ({len(audit.nrc_sunsi_blocked)}): {audit.nrc_sunsi_blocked}")
    print(f"Total returned: {len(docs)} / {audit.total_candidates} candidates")


# ---------------------------------------------------------------------------
# Document corpus
# ---------------------------------------------------------------------------

CORPUS: list[dict] = [
    # CEII — Critical Infrastructure docs
    {
        "id": "doc-001", "title": "500kV Substation GPS Coordinates and Asset Layout",
        "ceii_category": CEIICategory.CRITICAL_ASSET_LOCATION.value,
        "nerc_cip_tier": NERCCIPTier.HIGH_IMPACT.value,
        "sunsi_type": SUNSIType.NON_SUNSI.value,
    },
    {
        "id": "doc-002", "title": "EMS SCADA Architecture and Control Center Topology",
        "ceii_category": CEIICategory.CONTROL_SYSTEM.value,
        "nerc_cip_tier": NERCCIPTier.HIGH_IMPACT.value,
        "sunsi_type": SUNSIType.NON_SUNSI.value,
    },
    {
        "id": "doc-003", "title": "Transmission Protection System Relay Settings",
        "ceii_category": CEIICategory.PROTECTION_SYSTEM.value,
        "nerc_cip_tier": NERCCIPTier.MEDIUM_IMPACT.value,
        "sunsi_type": SUNSIType.NON_SUNSI.value,
    },
    {
        "id": "doc-004", "title": "Grid Vulnerability Assessment — N-2 Contingency Analysis",
        "ceii_category": CEIICategory.GRID_VULNERABILITY.value,
        "nerc_cip_tier": NERCCIPTier.HIGH_IMPACT.value,
        "sunsi_type": SUNSIType.NON_SUNSI.value,
    },
    # Nuclear — NRC SUNSI docs
    {
        "id": "doc-005", "title": "Nuclear Plant Physical Security Plan (SGI)",
        "ceii_category": CEIICategory.NON_CEII.value,
        "nerc_cip_tier": NERCCIPTier.NOT_APPLICABLE.value,
        "sunsi_type": SUNSIType.SAFEGUARDS_INFORMATION.value,
    },
    {
        "id": "doc-006", "title": "Spent Fuel Pool Security Procedures",
        "ceii_category": CEIICategory.NON_CEII.value,
        "nerc_cip_tier": NERCCIPTier.NOT_APPLICABLE.value,
        "sunsi_type": SUNSIType.SECURITY_RELATED_INFO.value,
    },
    # Non-sensitive BCSI (NERC CIP LOW)
    {
        "id": "doc-007", "title": "Distribution Automation SCADA Configuration",
        "ceii_category": CEIICategory.NON_CEII.value,
        "nerc_cip_tier": NERCCIPTier.LOW_IMPACT.value,
        "sunsi_type": SUNSIType.NON_SUNSI.value,
    },
    # Public information
    {
        "id": "doc-008", "title": "ISO-NE Day-Ahead Locational Marginal Prices (2024)",
        "ceii_category": CEIICategory.PUBLIC.value,
        "nerc_cip_tier": NERCCIPTier.NOT_APPLICABLE.value,
        "sunsi_type": SUNSIType.NON_SUNSI.value,
    },
    {
        "id": "doc-009", "title": "FERC Open Access Transmission Tariff — Schedule 1",
        "ceii_category": CEIICategory.PUBLIC.value,
        "nerc_cip_tier": NERCCIPTier.NOT_APPLICABLE.value,
        "sunsi_type": SUNSIType.NON_SUNSI.value,
    },
    {
        "id": "doc-010", "title": "Interconnection Queue Status Report Q1 2025",
        "ceii_category": CEIICategory.PUBLIC.value,
        "nerc_cip_tier": NERCCIPTier.NOT_APPLICABLE.value,
        "sunsi_type": SUNSIType.NON_SUNSI.value,
    },
]


# ---------------------------------------------------------------------------
# Main — four scenarios
# ---------------------------------------------------------------------------

def main() -> None:
    pipeline = EnergyRAGPipeline()

    # ------------------------------------------------------------------
    # Scenario A: Certified system operator — CIP-trained, CEII authorized
    # CEII passes. NERC CIP passes. NRC SUNSI blocks nuclear safeguards docs.
    # ------------------------------------------------------------------
    _print_scenario(
        "A",
        "Certified system operator (CEII//CRITICAL_ASSET + //CONTROL_SYSTEM authorized, "
        "CIP HIGH+MEDIUM trained). NRC SUNSI blocks nuclear safeguards. CEII + BCSI "
        "infrastructure docs returned.",
        "Show me the SCADA architecture and substation layout for the Northeast control area.",
    )
    ctx_a = EnergyAccessContext(
        user_id="op-1001",
        operator_role=OperatorRole.SYSTEM_OPERATOR,
        authorized_ceii_categories=frozenset({
            CEIICategory.CRITICAL_ASSET_LOCATION,
            CEIICategory.CONTROL_SYSTEM,
            CEIICategory.PROTECTION_SYSTEM,
            CEIICategory.GRID_VULNERABILITY,
        }),
        nerc_cip_training_complete=True,
        nerc_cip_authorized_tiers=frozenset({NERCCIPTier.HIGH_IMPACT, NERCCIPTier.MEDIUM_IMPACT}),
        nrc_sunsi_authorized=False,  # System operator ≠ NRC-authorized
    )
    docs_a, audit_a = pipeline.retrieve("SCADA and substation layout", CORPUS, ctx_a)
    _print_result(docs_a, audit_a)

    # ------------------------------------------------------------------
    # Scenario B: Third-party contractor — NERC CIP training not complete
    # CEII filter: no CEII authorization — blocks all CEII docs.
    # NERC CIP: training incomplete — blocks all BCSI (HIGH + MEDIUM + LOW).
    # NRC SUNSI: not authorized — blocks safeguards.
    # Only PUBLIC docs returned.
    # ------------------------------------------------------------------
    _print_scenario(
        "B",
        "Third-party EPC contractor (no CEII authorization, CIP training not complete). "
        "CEII blocks critical infrastructure docs. NERC CIP blocks all BCSI. "
        "Only public information returned.",
        "What are the grid topology and protection system configurations for substation X?",
    )
    ctx_b = EnergyAccessContext(
        user_id="vendor-ext-2201",
        operator_role=OperatorRole.THIRD_PARTY_CONTRACTOR,
        authorized_ceii_categories=frozenset(),
        nerc_cip_training_complete=False,
        nerc_cip_authorized_tiers=frozenset(),
        nrc_sunsi_authorized=False,
    )
    docs_b, audit_b = pipeline.retrieve("topology and protection system", CORPUS, ctx_b)
    _print_result(docs_b, audit_b)

    # ------------------------------------------------------------------
    # Scenario C: CIP Compliance Analyst — BCSI authorized, no CEII authorization
    # CEII: no CEII authorization — blocks CEII-tagged docs.
    # NERC CIP: training complete, ALL tiers authorized.
    # NRC SUNSI: not authorized.
    # LOW BCSI (doc-007) returned; CEII docs blocked despite CIP training.
    # ------------------------------------------------------------------
    _print_scenario(
        "C",
        "CIP Compliance Analyst (CIP-trained across all tiers, no FERC CEII authorization). "
        "CEII blocks critical asset and vulnerability docs. BCSI LOW passes. "
        "Public docs returned.",
        "Show me BCSI compliance documentation and distribution automation configurations.",
    )
    ctx_c = EnergyAccessContext(
        user_id="cip-analyst-3301",
        operator_role=OperatorRole.CIP_COMPLIANCE_ANALYST,
        authorized_ceii_categories=frozenset(),  # CIP compliance ≠ CEII authorization
        nerc_cip_training_complete=True,
        nerc_cip_authorized_tiers=frozenset({
            NERCCIPTier.HIGH_IMPACT,
            NERCCIPTier.MEDIUM_IMPACT,
            NERCCIPTier.LOW_IMPACT,
        }),
        nrc_sunsi_authorized=False,
    )
    docs_c, audit_c = pipeline.retrieve("BCSI compliance and distribution SCADA", CORPUS, ctx_c)
    _print_result(docs_c, audit_c)

    # ------------------------------------------------------------------
    # Scenario D: Public information request (ISO market pricing, FERC tariff)
    # All three layers pass for PUBLIC-tagged / NOT_APPLICABLE documents.
    # ------------------------------------------------------------------
    _print_scenario(
        "D",
        "Public information request (grid pricing, FERC tariff, interconnection queue). "
        "No CEII, no BCSI, no SUNSI designations. All three layers pass. "
        "Full public corpus returned.",
        "What are the day-ahead prices and interconnection queue status for Q1 2025?",
    )
    ctx_d = EnergyAccessContext(
        user_id="public-analyst-0001",
        operator_role=OperatorRole.PUBLIC,
        authorized_ceii_categories=frozenset(),
        nerc_cip_training_complete=False,
        nerc_cip_authorized_tiers=frozenset(),
        nrc_sunsi_authorized=False,
    )
    docs_d, audit_d = pipeline.retrieve("day-ahead prices and interconnection queue", CORPUS, ctx_d)
    _print_result(docs_d, audit_d)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("COMPLIANCE LAYER SUMMARY")
    print("=" * 70)
    print(f"{'Scenario':<12} {'Returned':<12} {'CEII blocked':<16} {'CIP blocked':<14} {'SUNSI blocked'}")
    print("-" * 70)
    for label, docs, audit in [
        ("A (operator)", docs_a, audit_a),
        ("B (contractor)", docs_b, audit_b),
        ("C (CIP analyst)", docs_c, audit_c),
        ("D (public)", docs_d, audit_d),
    ]:
        print(
            f"{label:<12} {len(docs):<12} {len(audit.ceii_blocked):<16} "
            f"{len(audit.nerc_cip_blocked):<14} {len(audit.nrc_sunsi_blocked)}"
        )

    print("\nApplicable regulations:")
    for reg in audit_a.applicable_regulations:
        print(f"  - {reg}")

    print("\nDesign notes:")
    print("  - CEII authorization is FERC-granted; NERC CIP training is a separate")
    print("    utility-internal process. A CIP compliance analyst may have CIP access")
    print("    without FERC CEII authorization — and vice versa.")
    print("  - NRC SUNSI authorization is NRC-granted; nuclear plant operators hold it")
    print("    independently of NERC or FERC authorizations.")
    print("  - Three-layer defense-in-depth: each layer blocks documents that pass")
    print("    the previous layer. No single authorization grants access to all docs.")


if __name__ == "__main__":
    main()
