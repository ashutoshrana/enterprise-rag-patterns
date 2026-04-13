"""
21_energy_utilities_rag.py — NERC CIP + FERC Order 2222 + NRC 10 CFR Part 73
compliance for an energy utility's operational knowledge base assistant.

Demonstrates defense-in-depth RAG retrieval where three overlapping regulatory
frameworks each impose independent access control obligations on an electric
utility information system:

    Layer 1  — NERC CIP v7 (North American Electric Reliability Corporation
               Critical Infrastructure Protection):
               Mandatory reliability standards for bulk electric system (BES)
               cyber security. CIP-004-7 requires personnel training and access
               management; CIP-007-7 requires port and service controls with
               electronic access lists; CIP-011-3 requires protection of BES
               Cyber System Information (BCSI). Only authorized, trained
               personnel may access BCSI. SCADA configurations, protection
               schemes, and network diagrams are classified BCSI.

    Layer 2  — FERC Order 2222 (Distributed Energy Resources, 2020):
               Requires Regional Transmission Organizations (RTOs) and
               Independent System Operators (ISOs) to allow aggregated
               Distributed Energy Resources (DERs) to participate in all
               organized wholesale electric markets. Market-sensitive data
               (dispatch curves, bidding strategies, capacity positions) is
               commercially sensitive and restricted to certified market
               participants to prevent market manipulation.

    Layer 3  — NRC 10 CFR Part 73.54 (Nuclear Cybersecurity, 2009):
               Licensees must provide high assurance that digital computer
               and communication systems and networks associated with nuclear
               safety functions are protected from cyber attacks. Critical
               Digital Assets (CDAs) associated with safety, security, or
               emergency preparedness functions require Q-level clearance or
               equivalent access authorization from the licensee.

Scenarios
---------

  A. Authorized control room operator queries SCADA configuration:
     NERC CIP: OPERATIONAL-level access with current training permitted.
     FERC Order 2222: SCADA data not market sensitive — pass-through.
     NRC: No nuclear CDAs in query scope — pass-through.
     Result: SCADA config and protection scheme documents returned.

  B. Unauthorized vendor queries network diagrams:
     NERC CIP: Vendor has PUBLIC access only — BCSI blocked.
     Result: Only public notices returned.

  C. Market analyst queries DER dispatch curves:
     NERC CIP: Dispatch curves not BCSI — pass-through.
     FERC Order 2222: Market analyst lacks certification — blocked.
     Result: Public market reports permitted; bid data blocked.

  D. Nuclear site admin queries reactor safety system documentation:
     NERC CIP: OPERATIONAL access with training — permit.
     NRC: Safety system requires Q-level clearance — check clearance.
     Result: Q-level cleared admin gets safety system docs.

No external dependencies required.

Run:
    python examples/21_energy_utilities_rag.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class BESCyberSystemImpactLevel(str, Enum):
    """
    NERC CIP BES Cyber System impact classification (CIP-002-5.1a).

    HIGH   — loss or compromise could affect BES reliability across multiple
             Control Areas or could result in misoperation of a Critical Asset
             in a widespread manner
    MEDIUM — impact limited to a single Control Area or could cause the
             degradation or loss of a single Critical Asset
    LOW    — impact limited to a single Facility or associated Electronic
             Security Perimeter
    NOT_APPLICABLE — not a BES Cyber System (e.g., administrative IT)
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class NERCCIPAccessLevel(str, Enum):
    """
    Personnel access level for NERC CIP purposes.

    OPERATIONAL — authorized access to high/medium BES Cyber Systems;
                  requires current annual CIP training (CIP-004-7)
    INFORMATIONAL — read access to BCSI for operational support roles;
                    requires CIP training
    PUBLIC — no BES Cyber System access; public documents only
    """
    OPERATIONAL = "OPERATIONAL"
    INFORMATIONAL = "INFORMATIONAL"
    PUBLIC = "PUBLIC"


class EnergyDocumentCategory(str, Enum):
    """
    Document categories in an energy utility knowledge base.
    Drives which regulatory filters apply.
    """
    # NERC CIP — BES Cyber System Information (BCSI)
    SCADA_CONFIG = "SCADA_CONFIG"             # EMS/DMS SCADA configuration
    PROTECTION_SCHEME = "PROTECTION_SCHEME"   # Relay protection settings
    NETWORK_DIAGRAM = "NETWORK_DIAGRAM"       # Electronic Access Point diagrams
    CYBER_SECURITY_PLAN = "CYBER_SECURITY_PLAN"  # CIP security plan
    ACCESS_CONTROL_LIST = "ACCESS_CONTROL_LIST"  # ACL / firewall rules
    # Operational non-BCSI
    MAINTENANCE_PROCEDURE = "MAINTENANCE_PROCEDURE"  # Equipment maintenance
    OPERATOR_LOG = "OPERATOR_LOG"             # Shift operator logs
    OUTAGE_REPORT = "OUTAGE_REPORT"           # Forced/planned outage reports
    EQUIPMENT_MANUAL = "EQUIPMENT_MANUAL"     # Vendor equipment manuals
    # FERC / Market data
    FERC_FILING = "FERC_FILING"               # Public FERC regulatory filings
    DER_DISPATCH_CURVE = "DER_DISPATCH_CURVE" # DER aggregation dispatch data
    MARKET_BID_DATA = "MARKET_BID_DATA"       # Wholesale market bid strategies
    CAPACITY_POSITION = "CAPACITY_POSITION"   # Portfolio capacity positions
    MARKET_REPORT_PUBLIC = "MARKET_REPORT_PUBLIC"  # Published market statistics
    # Nuclear (NRC)
    NUCLEAR_SAFETY_SYSTEM = "NUCLEAR_SAFETY_SYSTEM"  # Reactor protection docs
    CRITICAL_DIGITAL_ASSET = "CRITICAL_DIGITAL_ASSET"  # CDA documentation
    SECURITY_PLAN_NUCLEAR = "SECURITY_PLAN_NUCLEAR"  # Physical security plan
    EMERGENCY_PROCEDURE = "EMERGENCY_PROCEDURE"  # Emergency operating procedures
    # Public
    PUBLIC_NOTICE = "PUBLIC_NOTICE"           # NERC/FERC public notices
    ANNUAL_REPORT = "ANNUAL_REPORT"           # Public annual report


class ControlAreaType(str, Enum):
    """Type of control area for NERC CIP impact scoping."""
    TRANSMISSION = "TRANSMISSION"
    GENERATION = "GENERATION"
    DISTRIBUTION = "DISTRIBUTION"
    NUCLEAR = "NUCLEAR"
    MARKET = "MARKET"


# ---------------------------------------------------------------------------
# Access context and document model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnergyAccessContext:
    """
    Describes a personnel access request to the energy utility knowledge base.

    Attributes
    ----------
    personnel_id : str
    cip_access_level : NERCCIPAccessLevel
    nerc_training_current : bool
        True if annual CIP-004-7 cybersecurity training is current.
    authorized_asset_ids : tuple[str, ...]
        Specific BES Cyber System identifiers the personnel is authorized to access.
        Empty means no specific system authorization.
    market_participant_certified : bool
        True if the person holds RTO/ISO market participant certification for DER.
    nuclear_clearance : bool
        True if Q-level or equivalent nuclear access clearance is held.
    control_area_type : ControlAreaType
        The domain context of the query.
    """
    personnel_id: str
    cip_access_level: NERCCIPAccessLevel
    nerc_training_current: bool
    authorized_asset_ids: tuple[str, ...]
    market_participant_certified: bool
    nuclear_clearance: bool
    control_area_type: ControlAreaType


@dataclass(frozen=True)
class EnergyDocument:
    """
    A document in the energy utility knowledge base.

    Attributes
    ----------
    doc_id : str
    category : EnergyDocumentCategory
    title : str
    impact_level : BESCyberSystemImpactLevel
        CIP impact level of the BES Cyber System this doc relates to.
    bcsi_classification : bool
        True if document is BES Cyber System Information (BCSI) per CIP-011-3.
    is_nuclear_safety_system : bool
        True if document covers a safety, security, or emergency preparedness
        function at a nuclear facility (10 CFR 73.54 scope).
    requires_q_clearance : bool
        True if NRC Q-level or equivalent clearance is required.
    market_sensitive : bool
        True if document contains commercially sensitive market data.
    asset_id : str
        Identifier of the BES Cyber System or asset this doc belongs to.
        Empty string = not asset-specific.
    is_public : bool
        True for publicly available documents.
    """
    doc_id: str
    category: EnergyDocumentCategory
    title: str
    impact_level: BESCyberSystemImpactLevel = BESCyberSystemImpactLevel.NOT_APPLICABLE
    bcsi_classification: bool = False
    is_nuclear_safety_system: bool = False
    requires_q_clearance: bool = False
    market_sensitive: bool = False
    asset_id: str = ""
    is_public: bool = False


# ---------------------------------------------------------------------------
# Layer 1 — NERC CIP filter
# ---------------------------------------------------------------------------


class NERCCIPFilter:
    """
    Layer 1: NERC CIP v7 — BES Cyber Security Standards.

    Enforcement rules:
        CIP-004-7 (Personnel and Training):
            Any person with authorized access to BCSI must have completed the
            required annual cybersecurity training. Access is blocked for personnel
            with lapsed training regardless of their access level.

        CIP-007-7 (Systems Security Management):
            Electronic access to high/medium BES Cyber Systems is restricted to
            individuals on the authorized Electronic Access List (EAL). Only
            OPERATIONAL-level personnel may access high/medium BES system documents.

        CIP-011-3 (Information Protection):
            BCSI must only be accessible to personnel with CIP access authorization.
            PUBLIC-level personnel have no access to BCSI. INFORMATIONAL-level
            personnel may access informational BCSI (non-config, non-diagram).

    Public documents are not BCSI and are accessible regardless of access level.
    """

    # Categories that are always BCSI
    _BCSI_CATEGORIES: frozenset[EnergyDocumentCategory] = frozenset({
        EnergyDocumentCategory.SCADA_CONFIG,
        EnergyDocumentCategory.PROTECTION_SCHEME,
        EnergyDocumentCategory.NETWORK_DIAGRAM,
        EnergyDocumentCategory.CYBER_SECURITY_PLAN,
        EnergyDocumentCategory.ACCESS_CONTROL_LIST,
    })

    # Impact levels requiring OPERATIONAL access
    _OPERATIONAL_REQUIRED_LEVELS: frozenset[BESCyberSystemImpactLevel] = frozenset({
        BESCyberSystemImpactLevel.HIGH,
        BESCyberSystemImpactLevel.MEDIUM,
    })

    def filter(
        self,
        documents: list[EnergyDocument],
        context: EnergyAccessContext,
    ) -> tuple[list[EnergyDocument], list[str]]:
        permitted: list[EnergyDocument] = []
        reasons: list[str] = []

        for doc in documents:
            rejection = self._evaluate(doc, context)
            if rejection is None:
                permitted.append(doc)
            else:
                reasons.append(f"NERC CIP blocked {doc.doc_id}: {rejection}")

        return permitted, reasons

    def _evaluate(
        self,
        doc: EnergyDocument,
        context: EnergyAccessContext,
    ) -> Optional[str]:
        # Public documents are unrestricted
        if doc.is_public:
            return None

        # Non-BCSI, non-operational docs accessible by any non-PUBLIC level
        if not doc.bcsi_classification and not doc.asset_id:
            if context.cip_access_level == NERCCIPAccessLevel.PUBLIC:
                return (
                    "CIP-011-3 — PUBLIC-level personnel cannot access internal "
                    "utility documents; authorized access level required"
                )
            return None

        # BCSI check: PUBLIC cannot access any BCSI
        if doc.bcsi_classification and context.cip_access_level == NERCCIPAccessLevel.PUBLIC:
            return (
                "CIP-011-3 — BCSI (BES Cyber System Information) access requires "
                "CIP access authorization; PUBLIC access level insufficient"
            )

        # Training currency check for BCSI access (CIP-004-7 R4)
        if doc.bcsi_classification and not context.nerc_training_current:
            return (
                "CIP-004-7 R4 — annual cybersecurity training not current; "
                "BCSI access suspended until training is completed"
            )

        # HIGH/MEDIUM impact systems require OPERATIONAL access (CIP-007-7)
        if (
            doc.impact_level in self._OPERATIONAL_REQUIRED_LEVELS
            and context.cip_access_level != NERCCIPAccessLevel.OPERATIONAL
        ):
            return (
                f"CIP-007-7 — {doc.impact_level.value} impact BES Cyber System "
                f"requires OPERATIONAL access level; {context.cip_access_level.value} "
                f"access is insufficient"
            )

        # Asset-specific authorization check
        if (
            doc.asset_id
            and context.authorized_asset_ids
            and doc.asset_id not in context.authorized_asset_ids
        ):
            return (
                f"CIP-004-7 R4 — personnel not on Electronic Access List (EAL) "
                f"for asset {doc.asset_id}; individual authorization required"
            )

        return None


# ---------------------------------------------------------------------------
# Layer 2 — FERC Order 2222 filter
# ---------------------------------------------------------------------------


class FERCOrder2222Filter:
    """
    Layer 2: FERC Order 2222 (September 2020) — Participation of Distributed
    Energy Resource Aggregations in Markets Operated by RTOs/ISOs.

    Market-sensitive information about DER aggregation strategies, dispatch
    curves, bidding positions, and capacity holdings must not be accessed by
    non-certified market participants. Unauthorized access to bidding strategies
    could facilitate market manipulation (FERC Anti-Manipulation Rule, 18 CFR §1c.2).

    FERC public filings and market statistics reports are not restricted.

    Rules:
        - DER_DISPATCH_CURVE, MARKET_BID_DATA, CAPACITY_POSITION: require
          market_participant_certified=True
        - Any document with market_sensitive=True: requires certification
        - FERC_FILING and MARKET_REPORT_PUBLIC: accessible to all
    """

    _CERTIFIED_REQUIRED_CATEGORIES: frozenset[EnergyDocumentCategory] = frozenset({
        EnergyDocumentCategory.DER_DISPATCH_CURVE,
        EnergyDocumentCategory.MARKET_BID_DATA,
        EnergyDocumentCategory.CAPACITY_POSITION,
    })

    _PUBLIC_MARKET_CATEGORIES: frozenset[EnergyDocumentCategory] = frozenset({
        EnergyDocumentCategory.FERC_FILING,
        EnergyDocumentCategory.MARKET_REPORT_PUBLIC,
    })

    def filter(
        self,
        documents: list[EnergyDocument],
        context: EnergyAccessContext,
    ) -> tuple[list[EnergyDocument], list[str]]:
        permitted: list[EnergyDocument] = []
        reasons: list[str] = []

        for doc in documents:
            rejection = self._evaluate(doc, context)
            if rejection is None:
                permitted.append(doc)
            else:
                reasons.append(f"FERC Order 2222 blocked {doc.doc_id}: {rejection}")

        return permitted, reasons

    def _evaluate(
        self,
        doc: EnergyDocument,
        context: EnergyAccessContext,
    ) -> Optional[str]:
        # Public FERC filings and market reports are unrestricted
        if doc.is_public or doc.category in self._PUBLIC_MARKET_CATEGORIES:
            return None

        # Market-sensitive categories require certification
        if (
            doc.category in self._CERTIFIED_REQUIRED_CATEGORIES
            and not context.market_participant_certified
        ):
            return (
                "FERC Order 2222 / 18 CFR §1c.2 — market-sensitive DER aggregation "
                f"data ({doc.category.value}) restricted to certified RTO/ISO market "
                f"participants; market_participant_certified=False"
            )

        # Any document flagged market_sensitive requires certification
        if doc.market_sensitive and not context.market_participant_certified:
            return (
                "FERC Order 2222 — commercially sensitive market data requires "
                "RTO/ISO market participant certification to prevent market manipulation"
            )

        return None


# ---------------------------------------------------------------------------
# Layer 3 — NRC 10 CFR Part 73 cybersecurity filter
# ---------------------------------------------------------------------------


class NRCCybersecurityFilter:
    """
    Layer 3: NRC 10 CFR Part 73.54 — Protection of Digital Computer and
    Communication Systems and Networks.

    Nuclear licensees must provide high assurance that CDAs are protected from
    cyber attacks. CDAs are digital assets associated with safety (reactor protection,
    emergency core cooling), security (physical protection systems), or emergency
    preparedness functions at nuclear facilities.

    Access rules:
        - is_nuclear_safety_system=True: requires Q-level clearance
          (nuclear_clearance=True) regardless of NERC CIP access level
        - requires_q_clearance=True: requires nuclear_clearance=True
        - NUCLEAR_SAFETY_SYSTEM category: requires nuclear_clearance
        - CRITICAL_DIGITAL_ASSET and SECURITY_PLAN_NUCLEAR: requires nuclear_clearance
        - EMERGENCY_PROCEDURE: requires nuclear_clearance
        - Non-nuclear documents: pass-through (this filter only applies to nuclear)
    """

    _NUCLEAR_RESTRICTED_CATEGORIES: frozenset[EnergyDocumentCategory] = frozenset({
        EnergyDocumentCategory.NUCLEAR_SAFETY_SYSTEM,
        EnergyDocumentCategory.CRITICAL_DIGITAL_ASSET,
        EnergyDocumentCategory.SECURITY_PLAN_NUCLEAR,
        EnergyDocumentCategory.EMERGENCY_PROCEDURE,
    })

    def filter(
        self,
        documents: list[EnergyDocument],
        context: EnergyAccessContext,
    ) -> tuple[list[EnergyDocument], list[str]]:
        permitted: list[EnergyDocument] = []
        reasons: list[str] = []

        for doc in documents:
            rejection = self._evaluate(doc, context)
            if rejection is None:
                permitted.append(doc)
            else:
                reasons.append(f"NRC 73.54 blocked {doc.doc_id}: {rejection}")

        return permitted, reasons

    def _evaluate(
        self,
        doc: EnergyDocument,
        context: EnergyAccessContext,
    ) -> Optional[str]:
        # Public documents always permitted
        if doc.is_public:
            return None

        # Nuclear safety system access
        if doc.is_nuclear_safety_system and not context.nuclear_clearance:
            return (
                "10 CFR 73.54 — document associated with nuclear safety function "
                "(reactor protection, ECCS, or emergency preparedness); Q-level or "
                "equivalent access authorization required (nuclear_clearance=False)"
            )

        # Q-clearance required flag
        if doc.requires_q_clearance and not context.nuclear_clearance:
            return (
                "10 CFR 73.54 — document requires Q-level clearance or equivalent "
                "NRC access authorization; nuclear_clearance=False"
            )

        # Restricted category check
        if doc.category in self._NUCLEAR_RESTRICTED_CATEGORIES and not context.nuclear_clearance:
            return (
                f"10 CFR 73.54 — {doc.category.value} is a Critical Digital Asset "
                f"category requiring nuclear access authorization; "
                f"nuclear_clearance=False"
            )

        return None


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------


@dataclass
class EnergyComplianceAuditRecord:
    """
    Audit record for NERC CIP / FERC / NRC compliance purposes.

    NERC CIP requires evidence of access control (CIP-004-7 R6, CIP-007-7 R4).
    NRC requires access records for CDAs (10 CFR 73.54).
    """
    audit_id: str
    personnel_id: str
    control_area_type: ControlAreaType
    cip_access_level: NERCCIPAccessLevel
    training_current: bool
    nuclear_clearance: bool
    market_certified: bool
    documents_requested: int
    documents_permitted: int
    nerc_blocks: list[str]
    ferc_blocks: list[str]
    nrc_blocks: list[str]
    permitted_doc_ids: list[str]

    def to_cip_audit_log(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "personnel_id": self.personnel_id,
            "control_area": self.control_area_type.value,
            "cip_access_level": self.cip_access_level.value,
            "training_current": self.training_current,
            "nuclear_clearance": self.nuclear_clearance,
            "market_certified": self.market_certified,
            "requested": self.documents_requested,
            "permitted": self.documents_permitted,
            "nerc_blocks": len(self.nerc_blocks),
            "ferc_blocks": len(self.ferc_blocks),
            "nrc_blocks": len(self.nrc_blocks),
            "permitted_docs": self.permitted_doc_ids,
        }


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


class EnergyRAGPipeline:
    """
    Three-layer NERC CIP + FERC Order 2222 + NRC 10 CFR Part 73 pipeline.

    Layer execution:
        1. NERCCIPFilter      — BCSI access + training + impact level
        2. FERCOrder2222Filter — market data certification
        3. NRCCybersecurityFilter — nuclear CDA + Q-clearance

    Returns (permitted_docs, audit_record).
    """

    def __init__(self) -> None:
        self._nerc = NERCCIPFilter()
        self._ferc = FERCOrder2222Filter()
        self._nrc = NRCCybersecurityFilter()

    def retrieve(
        self,
        documents: list[EnergyDocument],
        context: EnergyAccessContext,
    ) -> tuple[list[EnergyDocument], EnergyComplianceAuditRecord]:
        total = len(documents)

        after_nerc, nerc_blocks = self._nerc.filter(documents, context)
        after_ferc, ferc_blocks = self._ferc.filter(after_nerc, context)
        after_nrc, nrc_blocks = self._nrc.filter(after_ferc, context)

        permitted = after_nrc
        audit = EnergyComplianceAuditRecord(
            audit_id=str(uuid.uuid4()),
            personnel_id=context.personnel_id,
            control_area_type=context.control_area_type,
            cip_access_level=context.cip_access_level,
            training_current=context.nerc_training_current,
            nuclear_clearance=context.nuclear_clearance,
            market_certified=context.market_participant_certified,
            documents_requested=total,
            documents_permitted=len(permitted),
            nerc_blocks=nerc_blocks,
            ferc_blocks=ferc_blocks,
            nrc_blocks=nrc_blocks,
            permitted_doc_ids=[d.doc_id for d in permitted],
        )
        return permitted, audit


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------


def _build_energy_knowledge_base() -> list[EnergyDocument]:
    return [
        # BCSI — SCADA and protection
        EnergyDocument(
            doc_id="SCADA-001",
            category=EnergyDocumentCategory.SCADA_CONFIG,
            title="EMS SCADA Configuration — Substation 44A",
            impact_level=BESCyberSystemImpactLevel.HIGH,
            bcsi_classification=True,
            asset_id="BES-TRANS-044",
        ),
        EnergyDocument(
            doc_id="PROT-001",
            category=EnergyDocumentCategory.PROTECTION_SCHEME,
            title="Distance Relay Settings — 230kV Line 7",
            impact_level=BESCyberSystemImpactLevel.HIGH,
            bcsi_classification=True,
            asset_id="BES-TRANS-044",
        ),
        EnergyDocument(
            doc_id="NET-001",
            category=EnergyDocumentCategory.NETWORK_DIAGRAM,
            title="Electronic Access Point Diagram — Control Center LAN",
            impact_level=BESCyberSystemImpactLevel.MEDIUM,
            bcsi_classification=True,
            asset_id="BES-CC-001",
        ),
        # Operational (non-BCSI)
        EnergyDocument(
            doc_id="MAINT-001",
            category=EnergyDocumentCategory.MAINTENANCE_PROCEDURE,
            title="Transformer Maintenance Procedure T-44",
            impact_level=BESCyberSystemImpactLevel.NOT_APPLICABLE,
            bcsi_classification=False,
        ),
        EnergyDocument(
            doc_id="LOG-001",
            category=EnergyDocumentCategory.OPERATOR_LOG,
            title="Shift Log — April 13, 2026 Day Shift",
        ),
        # Market data
        EnergyDocument(
            doc_id="DER-DISPATCH-001",
            category=EnergyDocumentCategory.DER_DISPATCH_CURVE,
            title="DER Aggregation Dispatch Curve — Zone 3",
            market_sensitive=True,
        ),
        EnergyDocument(
            doc_id="BID-001",
            category=EnergyDocumentCategory.MARKET_BID_DATA,
            title="Energy Bidding Strategy — Q2 2026",
            market_sensitive=True,
        ),
        EnergyDocument(
            doc_id="FERC-PUB-001",
            category=EnergyDocumentCategory.FERC_FILING,
            title="FERC Form 1 Annual Report 2025",
            is_public=True,
        ),
        EnergyDocument(
            doc_id="MARKET-RPT-001",
            category=EnergyDocumentCategory.MARKET_REPORT_PUBLIC,
            title="ISO-NE Monthly Market Statistics — March 2026",
            is_public=True,
        ),
        # Nuclear
        EnergyDocument(
            doc_id="NUC-SAFETY-001",
            category=EnergyDocumentCategory.NUCLEAR_SAFETY_SYSTEM,
            title="Reactor Protection System CDA Specification",
            is_nuclear_safety_system=True,
            requires_q_clearance=True,
            bcsi_classification=True,
            impact_level=BESCyberSystemImpactLevel.HIGH,
        ),
        EnergyDocument(
            doc_id="NUC-CDA-001",
            category=EnergyDocumentCategory.CRITICAL_DIGITAL_ASSET,
            title="Emergency Core Cooling System Digital Controller",
            is_nuclear_safety_system=True,
            requires_q_clearance=True,
        ),
        EnergyDocument(
            doc_id="EMRG-001",
            category=EnergyDocumentCategory.EMERGENCY_PROCEDURE,
            title="Emergency Operating Procedure EOP-E0 Loss of Coolant",
            is_nuclear_safety_system=True,
            requires_q_clearance=True,
        ),
        # Public
        EnergyDocument(
            doc_id="PUB-001",
            category=EnergyDocumentCategory.PUBLIC_NOTICE,
            title="NERC Reliability Standard CIP-004-7 Implementation Notice",
            is_public=True,
        ),
        EnergyDocument(
            doc_id="PUB-002",
            category=EnergyDocumentCategory.ANNUAL_REPORT,
            title="Utility Annual Report 2025",
            is_public=True,
        ),
    ]


def run_scenario_a_control_room_operator() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO A: Authorized Control Room Operator — SCADA Query")
    print("=" * 70)

    context = EnergyAccessContext(
        personnel_id="CRO-TX-0441",
        cip_access_level=NERCCIPAccessLevel.OPERATIONAL,
        nerc_training_current=True,
        authorized_asset_ids=("BES-TRANS-044", "BES-CC-001"),
        market_participant_certified=False,
        nuclear_clearance=False,
        control_area_type=ControlAreaType.TRANSMISSION,
    )

    kb = _build_energy_knowledge_base()
    pipeline = EnergyRAGPipeline()
    permitted, audit = pipeline.retrieve(kb, context)

    print(f"\nDocuments requested : {audit.documents_requested}")
    print(f"Documents permitted : {audit.documents_permitted}")
    print(f"\nNERC CIP blocks ({len(audit.nerc_blocks)}):")
    for r in audit.nerc_blocks:
        print(f"  {r}")
    print(f"\nFERC blocks ({len(audit.ferc_blocks)}):")
    for r in audit.ferc_blocks:
        print(f"  {r}")
    print(f"\nNRC blocks ({len(audit.nrc_blocks)}):")
    for r in audit.nrc_blocks:
        print(f"  {r}")
    print(f"\nPermitted documents ({len(permitted)}):")
    for d in permitted:
        print(f"  [{d.category.value}] {d.doc_id}: {d.title}")


def run_scenario_b_unauthorized_vendor() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO B: Unauthorized Vendor — Network Diagram Query (NERC CIP Block)")
    print("=" * 70)

    context = EnergyAccessContext(
        personnel_id="VENDOR-EXT-9901",
        cip_access_level=NERCCIPAccessLevel.PUBLIC,
        nerc_training_current=False,
        authorized_asset_ids=(),
        market_participant_certified=False,
        nuclear_clearance=False,
        control_area_type=ControlAreaType.TRANSMISSION,
    )

    kb = _build_energy_knowledge_base()
    pipeline = EnergyRAGPipeline()
    permitted, audit = pipeline.retrieve(kb, context)

    print(f"\nDocuments requested : {audit.documents_requested}")
    print(f"Documents permitted : {audit.documents_permitted}")
    print(f"\nNERC CIP blocks ({len(audit.nerc_blocks)}) (showing first 5):")
    for r in audit.nerc_blocks[:5]:
        print(f"  {r}")
    if len(audit.nerc_blocks) > 5:
        print(f"  ... and {len(audit.nerc_blocks) - 5} more")
    print(f"\nPermitted documents ({len(permitted)}):")
    for d in permitted:
        print(f"  [{d.category.value}] {d.doc_id}: {d.title}")


def run_scenario_c_market_analyst_der() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO C: Market Analyst — DER Dispatch Curve Query (FERC Order 2222)")
    print("=" * 70)

    context = EnergyAccessContext(
        personnel_id="MKTG-ANALYST-007",
        cip_access_level=NERCCIPAccessLevel.INFORMATIONAL,
        nerc_training_current=True,
        authorized_asset_ids=(),
        market_participant_certified=False,  # Not certified!
        nuclear_clearance=False,
        control_area_type=ControlAreaType.MARKET,
    )

    kb = _build_energy_knowledge_base()
    pipeline = EnergyRAGPipeline()
    permitted, audit = pipeline.retrieve(kb, context)

    print(f"\nDocuments requested : {audit.documents_requested}")
    print(f"Documents permitted : {audit.documents_permitted}")
    print(f"\nFERC blocks ({len(audit.ferc_blocks)}):")
    for r in audit.ferc_blocks:
        print(f"  {r}")
    print(f"\nPermitted documents ({len(permitted)}):")
    for d in permitted:
        print(f"  [{d.category.value}] {d.doc_id}: {d.title}")


def run_scenario_d_nuclear_admin() -> None:
    print("\n" + "=" * 70)
    print("SCENARIO D: Nuclear Site Admin — Safety System Query (NRC 10 CFR 73.54)")
    print("=" * 70)

    context = EnergyAccessContext(
        personnel_id="NUC-ADMIN-881",
        cip_access_level=NERCCIPAccessLevel.OPERATIONAL,
        nerc_training_current=True,
        authorized_asset_ids=("BES-TRANS-044",),
        market_participant_certified=False,
        nuclear_clearance=True,  # Q-cleared
        control_area_type=ControlAreaType.NUCLEAR,
    )

    kb = _build_energy_knowledge_base()
    pipeline = EnergyRAGPipeline()
    permitted, audit = pipeline.retrieve(kb, context)

    print(f"\nDocuments requested : {audit.documents_requested}")
    print(f"Documents permitted : {audit.documents_permitted}")
    print(f"\nNRC blocks ({len(audit.nrc_blocks)}):")
    for r in audit.nrc_blocks:
        print(f"  {r}")
    print(f"\nPermitted documents ({len(permitted)}):")
    for d in permitted:
        print(f"  [{d.category.value}] {d.doc_id}: {d.title}")


if __name__ == "__main__":
    print("Energy / Utilities RAG — NERC CIP + FERC Order 2222 + NRC 10 CFR Part 73")
    print("Three-layer defense-in-depth pipeline")

    run_scenario_a_control_room_operator()
    run_scenario_b_unauthorized_vendor()
    run_scenario_c_market_analyst_der()
    run_scenario_d_nuclear_admin()

    print("\n" + "=" * 70)
    print("All scenarios complete.")
    print("=" * 70)
