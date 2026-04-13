"""
22_government_contracting_rag.py — FAR/DFARS CUI + ITAR/EAR export control +
DD Form 254 need-to-know compliance for a government contractor knowledge base
assistant.

Demonstrates defense-in-depth RAG retrieval where three overlapping regulatory
frameworks each impose independent access control obligations on a cleared
defense contractor information system:

    Layer 1  — FAR/DFARS CUI (Federal Acquisition Regulation /
               Defense Federal Acquisition Regulation Supplement):
               FAR 52.204-21 and DFARS 252.204-7012 require contractors
               handling federal contract information and Controlled
               Unclassified Information (CUI) to protect data against
               unauthorized access. CUI categories (NIST SP 800-171) define
               mandatory access controls; Facility Clearance (FCL) and
               individual personnel security clearance levels gate access
               to classified information above CUI.

    Layer 2  — ITAR/EAR export control:
               International Traffic in Arms Regulations (22 CFR Parts
               120-130) restrict USML-listed defense articles and technical
               data to US Persons unless a license or exemption applies.
               Export Administration Regulations (15 CFR Parts 730-774)
               govern dual-use items via the Commerce Control List (CCL).
               Foreign nationals may not access ITAR-controlled USML
               technical data without a license from the Directorate of
               Defense Trade Controls (DDTC). EAR99 items are unrestricted;
               CCL items require license review based on reason-for-control
               and destination.

    Layer 3  — DD Form 254 need-to-know:
               DoD Contract Security Classification Specification (DD 254)
               defines the classification level and categories authorized
               for a specific contract. Contractors are authorized to access
               classified information only to the extent required to perform
               their specific contract — a personnel clearance is necessary
               but not sufficient. The contractor must also have an active
               contract assignment that covers the required access category.

Scenarios
---------

  A. US-citizen senior engineer on cleared contract queries ITAR USML spec:
     FAR/DFARS: SECRET FCL + personnel clearance — permit.
     ITAR: US Person + USML authorized list — permit.
     DD 254: Contract assignment covers technical category — permit.
     Result: USML technical data returned.

  B. Foreign national employee queries ITAR USML drawing:
     ITAR: Non-US Person — USML blocked (no deemed export license).
     Result: Only EAR99 / uncontrolled documents returned.

  C. Cleared contractor queries CUI on unrelated contract:
     DD 254: No contract assignment for required category.
     Result: CUI document blocked regardless of clearance.

  D. Cleared contractor queries EAR CCL dual-use item:
     FAR/DFARS: CUI category permitted — pass-through.
     ITAR: Not USML — pass-through.
     EAR: CCL AT-only control; recipient is domestic — permit.
     Result: Dual-use technical data returned.

No external dependencies required.

Run:
    python examples/22_government_contracting_rag.py
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Optional


# ---------------------------------------------------------------------------
# Domain enumerations
# ---------------------------------------------------------------------------


class SecurityClearanceLevel(str, Enum):
    """Personnel and facility security clearance levels."""

    UNCLASSIFIED = "UNCLASSIFIED"
    CUI = "CUI"              # Controlled Unclassified Information
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"
    TOP_SECRET_SCI = "TOP_SECRET_SCI"

    @property
    def rank(self) -> int:
        _rank = {
            "UNCLASSIFIED": 0,
            "CUI": 1,
            "CONFIDENTIAL": 2,
            "SECRET": 3,
            "TOP_SECRET": 4,
            "TOP_SECRET_SCI": 5,
        }
        return _rank[self.value]

    def authorizes(self, required: "SecurityClearanceLevel") -> bool:
        """Return True if this clearance level covers the required level."""
        return self.rank >= required.rank


class CUICategory(str, Enum):
    """
    NIST SP 800-171 / CUI Registry categories relevant to defense contracts.
    """

    CONTROLLED_TECHNICAL_INFORMATION = "CTI"         # DFARS 252.204-7012
    EXPORT_CONTROLLED = "EXPORT_CONTROLLED"
    PRIVACY = "PRIVACY"
    PROPRIETARY_BUSINESS_INFORMATION = "PBI"
    LAW_ENFORCEMENT_SENSITIVE = "LES"
    NUCLEAR = "NUCLEAR"
    SPECIFIED_BASIC = "SPECIFIED_BASIC"               # Basic CUI, no special handling
    UNCONTROLLED = "UNCONTROLLED"                     # Not CUI


class ITARCategory(str, Enum):
    """
    USML categories (22 CFR Part 121) and EAR CCL export control tiers.
    USML = United States Munitions List (ITAR-controlled).
    CCL  = Commerce Control List (EAR-controlled).
    """

    # ITAR USML categories
    USML_I_FIREARMS = "USML_I"            # Category I — Firearms
    USML_II_GUNS = "USML_II"             # Category II — Guns and Armament
    USML_III_AMMUNITION = "USML_III"     # Category III — Ammunition
    USML_IV_AIRCRAFT = "USML_IV"         # Category IV — Aircraft
    USML_VIII_AIRCRAFT_TECH = "USML_VIII" # Category VIII — Aircraft / gas turbine
    USML_XI_MILITARY_ELECTRONICS = "USML_XI"  # Category XI
    USML_XII_OPTICS = "USML_XII"         # Category XII — Fire control, lasers
    USML_XV_SPACECRAFT = "USML_XV"       # Category XV — Spacecraft
    USML_XXII_SUBMERSIBLES = "USML_XXII" # Category XXII — Submersibles

    # EAR CCL tiers
    CCL_AT_ONLY = "CCL_AT"              # Anti-Terrorism controls only
    CCL_NS_MT = "CCL_NS_MT"            # National Security / Missile Technology
    CCL_DUAL_USE = "CCL_DUAL_USE"      # Dual-use, multiple reasons-for-control
    EAR99 = "EAR99"                    # EAR99 — no CCL entry, no license required
    NOT_SUBJECT_EAR = "NOT_SUBJECT_EAR"  # Not subject to EAR (e.g., published info)


# ITAR USML categories that require US Person access or a deemed-export license
_USML_CATEGORIES: FrozenSet[ITARCategory] = frozenset({
    ITARCategory.USML_I_FIREARMS,
    ITARCategory.USML_II_GUNS,
    ITARCategory.USML_III_AMMUNITION,
    ITARCategory.USML_IV_AIRCRAFT,
    ITARCategory.USML_VIII_AIRCRAFT_TECH,
    ITARCategory.USML_XI_MILITARY_ELECTRONICS,
    ITARCategory.USML_XII_OPTICS,
    ITARCategory.USML_XV_SPACECRAFT,
    ITARCategory.USML_XXII_SUBMERSIBLES,
})

# EAR CCL categories that require license review for non-domestic recipients
_CCL_RESTRICTED_CATEGORIES: FrozenSet[ITARCategory] = frozenset({
    ITARCategory.CCL_NS_MT,
    ITARCategory.CCL_DUAL_USE,
})


# ---------------------------------------------------------------------------
# Context and document dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContractorAccessContext:
    """
    Runtime context representing the contractor employee submitting a query.

    Attributes
    ----------
    contractor_id : str
        Unique identifier for this contractor/employee account.
    is_us_person : bool
        True if the individual is a US Person under ITAR (US citizen, LPR,
        refugee/asylee, or US corporation). Foreign nationals are non-US Persons
        and may not access USML data without a deemed-export license.
    personnel_clearance : SecurityClearanceLevel
        The individual's DoD personnel security clearance level.
    facility_clearance : SecurityClearanceLevel
        The facility (FCL) clearance level of the contractor's cleared facility.
    cui_categories_authorized : FrozenSet[CUICategory]
        CUI categories this individual is authorized to access under their
        DFARS 252.204-7012 system security plan.
    authorized_contract_ids : FrozenSet[str]
        Set of active DD Form 254 contract numbers assigned to this individual.
    has_deemed_export_license : bool
        True if a DDTC deemed-export license is on file for this individual
        covering access to ITAR-controlled USML technical data.
    is_domestic_recipient : bool
        True if the query originates from a domestic (US) location. EAR CCL
        NS/MT items require additional review for foreign recipients.
    """

    contractor_id: str
    is_us_person: bool
    personnel_clearance: SecurityClearanceLevel
    facility_clearance: SecurityClearanceLevel
    cui_categories_authorized: FrozenSet[CUICategory]
    authorized_contract_ids: FrozenSet[str]
    has_deemed_export_license: bool = False
    is_domestic_recipient: bool = True


@dataclass(frozen=True)
class GovContractDocument:
    """
    A document in the government contractor knowledge base.

    Attributes
    ----------
    document_id : str
        Unique document identifier.
    title : str
        Document title.
    minimum_clearance : SecurityClearanceLevel
        Minimum personnel clearance required to access this document.
    cui_category : CUICategory
        CUI handling category for this document.
    itar_category : ITARCategory
        ITAR/EAR export control classification.
    required_contract_ids : FrozenSet[str]
        Set of contract numbers (DD 254) that authorize access to this
        document. Empty frozenset means no contract-specific restriction
        (e.g., unclassified / non-CUI reference material).
    requires_facility_clearance : SecurityClearanceLevel
        Minimum facility clearance for the document's cleared facility.
    is_publicly_releasable : bool
        True if this document has been approved for public release (e.g.,
        published technical reports, press releases).
    """

    document_id: str
    title: str
    minimum_clearance: SecurityClearanceLevel
    cui_category: CUICategory
    itar_category: ITARCategory
    required_contract_ids: FrozenSet[str]
    requires_facility_clearance: SecurityClearanceLevel = SecurityClearanceLevel.UNCLASSIFIED
    is_publicly_releasable: bool = False


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------


@dataclass
class GovContractComplianceAuditRecord:
    """
    Audit record for a government contractor RAG retrieval event.

    Records the complete access control decision for each document, including
    which regulatory layer blocked or permitted access.
    """

    query_id: str
    contractor_id: str
    total_candidates: int = 0
    far_dfars_permitted: int = 0
    far_dfars_blocked: int = 0
    itar_ear_permitted: int = 0
    itar_ear_blocked: int = 0
    dd254_permitted: int = 0
    dd254_blocked: int = 0
    final_permitted: int = 0
    final_blocked: int = 0
    block_reasons: list = field(default_factory=list)

    def to_audit_log(self) -> dict:
        return {
            "query_id": self.query_id,
            "contractor_id": self.contractor_id,
            "total_candidates": self.total_candidates,
            "layers": {
                "far_dfars": {
                    "permitted": self.far_dfars_permitted,
                    "blocked": self.far_dfars_blocked,
                },
                "itar_ear": {
                    "permitted": self.itar_ear_permitted,
                    "blocked": self.itar_ear_blocked,
                },
                "dd254": {
                    "permitted": self.dd254_permitted,
                    "blocked": self.dd254_blocked,
                },
            },
            "final": {
                "permitted": self.final_permitted,
                "blocked": self.final_blocked,
            },
            "block_reasons": self.block_reasons,
        }


# ---------------------------------------------------------------------------
# Layer 1 — FAR/DFARS CUI filter
# ---------------------------------------------------------------------------


class FARDFARSFilter:
    """
    Layer 1: FAR 52.204-21 / DFARS 252.204-7012 CUI and clearance access control.

    Enforces:
    - Facility clearance check: FCL must meet or exceed document requirement
    - Personnel clearance check: individual clearance must meet minimum
    - CUI category authorization: individual must be authorized for the
      document's CUI handling category
    - Publicly releasable documents pass regardless of clearance

    References
    ----------
    FAR 52.204-21 — Basic Safeguarding of Covered Contractor Information Systems
    DFARS 252.204-7012 — Safeguarding Covered Defense Information
    NIST SP 800-171 — Protecting CUI in Nonfederal Systems
    """

    def _evaluate(
        self,
        doc: GovContractDocument,
        ctx: ContractorAccessContext,
    ) -> Optional[str]:
        """
        Return a block reason string, or None if the document is permitted.
        """
        if doc.is_publicly_releasable:
            return None

        # Facility clearance check
        if not ctx.facility_clearance.authorizes(doc.requires_facility_clearance):
            return (
                f"FAR/DFARS: Facility clearance {ctx.facility_clearance.value} "
                f"does not meet document requirement "
                f"{doc.requires_facility_clearance.value} "
                f"[DFARS 252.204-7012]"
            )

        # Personnel clearance check
        if not ctx.personnel_clearance.authorizes(doc.minimum_clearance):
            return (
                f"FAR/DFARS: Personnel clearance {ctx.personnel_clearance.value} "
                f"insufficient for document minimum "
                f"{doc.minimum_clearance.value}"
            )

        # CUI category authorization
        if (
            doc.cui_category != CUICategory.UNCONTROLLED
            and doc.cui_category not in ctx.cui_categories_authorized
        ):
            return (
                f"FAR/DFARS: CUI category {doc.cui_category.value} not in "
                f"authorized categories [NIST SP 800-171]"
            )

        return None

    def filter(
        self,
        documents: list[GovContractDocument],
        context: ContractorAccessContext,
        audit: GovContractComplianceAuditRecord,
    ) -> list[GovContractDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
                audit.far_dfars_permitted += 1
            else:
                audit.far_dfars_blocked += 1
                audit.block_reasons.append(
                    {"document_id": doc.document_id, "layer": "FAR_DFARS", "reason": reason}
                )
        return permitted


# ---------------------------------------------------------------------------
# Layer 2 — ITAR/EAR export control filter
# ---------------------------------------------------------------------------


class ITAREARFilter:
    """
    Layer 2: ITAR (22 CFR Parts 120-130) and EAR (15 CFR Parts 730-774)
    export control access filter.

    Enforces:
    - USML technical data: requires US Person status or a deemed-export license
    - CCL NS/MT items: requires domestic recipient for unrestricted access
    - EAR99 and NOT_SUBJECT_EAR: no restriction
    - USML with deemed-export license: permitted for foreign nationals

    References
    ----------
    22 CFR Part 120 — ITAR Definitions
    22 CFR Part 121 — USML Categories
    22 CFR Part 124 — Agreements, Off-Shore Procurement, and Related Authorizations
    15 CFR Part 734 — Scope of the EAR
    15 CFR Part 738 — CCL Overview and the Country Chart
    """

    def _evaluate(
        self,
        doc: GovContractDocument,
        ctx: ContractorAccessContext,
    ) -> Optional[str]:
        if doc.is_publicly_releasable:
            return None

        # ITAR USML check
        if doc.itar_category in _USML_CATEGORIES:
            if not ctx.is_us_person and not ctx.has_deemed_export_license:
                return (
                    f"ITAR: Document contains USML {doc.itar_category.value} "
                    f"technical data; non-US Person access requires deemed-export "
                    f"license from DDTC [22 CFR §124.16]"
                )

        # EAR CCL NS/MT — foreign recipient restriction
        if doc.itar_category in _CCL_RESTRICTED_CATEGORIES:
            if not ctx.is_domestic_recipient:
                return (
                    f"EAR: CCL item {doc.itar_category.value} requires license "
                    f"review for non-domestic recipients "
                    f"[15 CFR Parts 738-744]"
                )

        return None

    def filter(
        self,
        documents: list[GovContractDocument],
        context: ContractorAccessContext,
        audit: GovContractComplianceAuditRecord,
    ) -> list[GovContractDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
                audit.itar_ear_permitted += 1
            else:
                audit.itar_ear_blocked += 1
                audit.block_reasons.append(
                    {"document_id": doc.document_id, "layer": "ITAR_EAR", "reason": reason}
                )
        return permitted


# ---------------------------------------------------------------------------
# Layer 3 — DD Form 254 need-to-know filter
# ---------------------------------------------------------------------------


class DD254NeedToKnowFilter:
    """
    Layer 3: DoD Contract Security Classification Specification (DD Form 254)
    need-to-know access control.

    A valid personnel clearance is necessary but not sufficient to access
    classified or CUI information on a government contract. The contractor
    must also have a current contract assignment (DD 254) that authorizes
    access to the specific category of information required.

    This prevents "clearance shopping" — using one contract's clearance to
    access information for an unrelated contract.

    References
    ----------
    DoD 5220.22-M — National Industrial Security Program Operating Manual
    NISPOM Rule (32 CFR Part 117) — National Industrial Security Program
    DD Form 254 — DoD Contract Security Classification Specification
    """

    def _evaluate(
        self,
        doc: GovContractDocument,
        ctx: ContractorAccessContext,
    ) -> Optional[str]:
        if doc.is_publicly_releasable:
            return None

        # No contract restriction — open to all cleared personnel
        if not doc.required_contract_ids:
            return None

        # Check if contractor has any of the required contract assignments
        if not doc.required_contract_ids.intersection(ctx.authorized_contract_ids):
            return (
                f"DD Form 254: Document requires active contract assignment "
                f"from {set(doc.required_contract_ids)}; contractor has "
                f"{set(ctx.authorized_contract_ids)} "
                f"[NISPOM Rule 32 CFR §117.18]"
            )

        return None

    def filter(
        self,
        documents: list[GovContractDocument],
        context: ContractorAccessContext,
        audit: GovContractComplianceAuditRecord,
    ) -> list[GovContractDocument]:
        permitted = []
        for doc in documents:
            reason = self._evaluate(doc, context)
            if reason is None:
                permitted.append(doc)
                audit.dd254_permitted += 1
            else:
                audit.dd254_blocked += 1
                audit.block_reasons.append(
                    {"document_id": doc.document_id, "layer": "DD254", "reason": reason}
                )
        return permitted


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


class GovContractRAGPipeline:
    """
    Three-layer defense-in-depth RAG pipeline for government contractor
    knowledge base systems.

    Retrieval order:
        FAR/DFARS CUI + clearance  →  ITAR/EAR export control  →  DD 254

    All three layers must permit a document before it is returned to the caller.
    Any single block prevents retrieval. The audit record captures per-layer
    statistics for DCSA compliance reporting.
    """

    def __init__(self) -> None:
        self._far_dfars = FARDFARSFilter()
        self._itar_ear = ITAREARFilter()
        self._dd254 = DD254NeedToKnowFilter()

    def retrieve(
        self,
        candidates: list[GovContractDocument],
        context: ContractorAccessContext,
    ) -> tuple[list[GovContractDocument], GovContractComplianceAuditRecord]:
        """
        Apply all three compliance layers and return permitted documents
        plus a complete audit record.
        """
        audit = GovContractComplianceAuditRecord(
            query_id=str(uuid.uuid4()),
            contractor_id=context.contractor_id,
            total_candidates=len(candidates),
        )

        after_far = self._far_dfars.filter(candidates, context, audit)
        after_itar = self._itar_ear.filter(after_far, context, audit)
        final = self._dd254.filter(after_itar, context, audit)

        audit.final_permitted = len(final)
        audit.final_blocked = len(candidates) - len(final)

        return final, audit


# ---------------------------------------------------------------------------
# Scenario demonstrations
# ---------------------------------------------------------------------------

def _make_document_corpus() -> list[GovContractDocument]:
    return [
        GovContractDocument(
            document_id="D-001",
            title="F-35 Avionics Integration Specification (USML IV)",
            minimum_clearance=SecurityClearanceLevel.SECRET,
            cui_category=CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
            itar_category=ITARCategory.USML_IV_AIRCRAFT,
            required_contract_ids=frozenset({"FA8625-24-C-0001"}),
            requires_facility_clearance=SecurityClearanceLevel.SECRET,
        ),
        GovContractDocument(
            document_id="D-002",
            title="Satellite Payload Component Drawing (USML XV)",
            minimum_clearance=SecurityClearanceLevel.SECRET,
            cui_category=CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
            itar_category=ITARCategory.USML_XV_SPACECRAFT,
            required_contract_ids=frozenset({"HQ0147-23-C-0077"}),
            requires_facility_clearance=SecurityClearanceLevel.SECRET,
        ),
        GovContractDocument(
            document_id="D-003",
            title="Dual-Use Laser Range Finder Technical Manual (CCL NS/MT)",
            minimum_clearance=SecurityClearanceLevel.CUI,
            cui_category=CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
            itar_category=ITARCategory.CCL_NS_MT,
            required_contract_ids=frozenset({"W31P4Q-24-C-0032"}),
            requires_facility_clearance=SecurityClearanceLevel.CUI,
        ),
        GovContractDocument(
            document_id="D-004",
            title="Proprietary Supplier Pricing and Cost Breakdown",
            minimum_clearance=SecurityClearanceLevel.CUI,
            cui_category=CUICategory.PROPRIETARY_BUSINESS_INFORMATION,
            itar_category=ITARCategory.EAR99,
            required_contract_ids=frozenset(),
            requires_facility_clearance=SecurityClearanceLevel.CUI,
        ),
        GovContractDocument(
            document_id="D-005",
            title="Unclassified Technical Reference Manual (EAR99)",
            minimum_clearance=SecurityClearanceLevel.UNCLASSIFIED,
            cui_category=CUICategory.UNCONTROLLED,
            itar_category=ITARCategory.EAR99,
            required_contract_ids=frozenset(),
        ),
        GovContractDocument(
            document_id="D-006",
            title="Approved-for-Release Press Fact Sheet",
            minimum_clearance=SecurityClearanceLevel.UNCLASSIFIED,
            cui_category=CUICategory.UNCONTROLLED,
            itar_category=ITARCategory.NOT_SUBJECT_EAR,
            required_contract_ids=frozenset(),
            is_publicly_releasable=True,
        ),
    ]


def scenario_a_cleared_us_engineer() -> None:
    """US-citizen SECRET-cleared engineer with correct contract assignment."""
    print("\n--- Scenario A: Cleared US Engineer (SECRET, F-35 contract) ---")
    pipeline = GovContractRAGPipeline()
    corpus = _make_document_corpus()
    ctx = ContractorAccessContext(
        contractor_id="ENG-001",
        is_us_person=True,
        personnel_clearance=SecurityClearanceLevel.SECRET,
        facility_clearance=SecurityClearanceLevel.SECRET,
        cui_categories_authorized=frozenset({
            CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
            CUICategory.PROPRIETARY_BUSINESS_INFORMATION,
        }),
        authorized_contract_ids=frozenset({"FA8625-24-C-0001"}),
        is_domestic_recipient=True,
    )
    docs, audit = pipeline.retrieve(corpus, ctx)
    print(f"  Permitted: {[d.document_id for d in docs]}")
    print(f"  Blocked: {audit.final_blocked}")
    for r in audit.block_reasons:
        print(f"    {r['document_id']}: {r['reason'][:80]}...")


def scenario_b_foreign_national() -> None:
    """Foreign national with CUI clearance — blocked from USML data."""
    print("\n--- Scenario B: Foreign National (no deemed-export license) ---")
    pipeline = GovContractRAGPipeline()
    corpus = _make_document_corpus()
    ctx = ContractorAccessContext(
        contractor_id="ENG-002",
        is_us_person=False,
        personnel_clearance=SecurityClearanceLevel.SECRET,
        facility_clearance=SecurityClearanceLevel.SECRET,
        cui_categories_authorized=frozenset({
            CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
            CUICategory.PROPRIETARY_BUSINESS_INFORMATION,
        }),
        authorized_contract_ids=frozenset({
            "FA8625-24-C-0001", "HQ0147-23-C-0077", "W31P4Q-24-C-0032"
        }),
        is_domestic_recipient=True,
    )
    docs, audit = pipeline.retrieve(corpus, ctx)
    print(f"  Permitted: {[d.document_id for d in docs]}")
    print(f"  ITAR/EAR blocked: {audit.itar_ear_blocked}")


def scenario_c_wrong_contract() -> None:
    """Cleared US engineer but wrong contract assignment."""
    print("\n--- Scenario C: Cleared Engineer — Wrong Contract (DD 254 block) ---")
    pipeline = GovContractRAGPipeline()
    corpus = _make_document_corpus()
    ctx = ContractorAccessContext(
        contractor_id="ENG-003",
        is_us_person=True,
        personnel_clearance=SecurityClearanceLevel.SECRET,
        facility_clearance=SecurityClearanceLevel.SECRET,
        cui_categories_authorized=frozenset({
            CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
            CUICategory.PROPRIETARY_BUSINESS_INFORMATION,
        }),
        authorized_contract_ids=frozenset({"W9124P-24-C-0099"}),  # unrelated contract
        is_domestic_recipient=True,
    )
    docs, audit = pipeline.retrieve(corpus, ctx)
    print(f"  Permitted: {[d.document_id for d in docs]}")
    print(f"  DD254 blocked: {audit.dd254_blocked}")


def scenario_d_foreign_with_license() -> None:
    """Foreign national with deemed-export license — USML permitted."""
    print("\n--- Scenario D: Foreign National WITH Deemed-Export License ---")
    pipeline = GovContractRAGPipeline()
    corpus = _make_document_corpus()
    ctx = ContractorAccessContext(
        contractor_id="ENG-004",
        is_us_person=False,
        personnel_clearance=SecurityClearanceLevel.SECRET,
        facility_clearance=SecurityClearanceLevel.SECRET,
        cui_categories_authorized=frozenset({
            CUICategory.CONTROLLED_TECHNICAL_INFORMATION,
            CUICategory.PROPRIETARY_BUSINESS_INFORMATION,
        }),
        authorized_contract_ids=frozenset({
            "FA8625-24-C-0001", "HQ0147-23-C-0077", "W31P4Q-24-C-0032"
        }),
        has_deemed_export_license=True,
        is_domestic_recipient=True,
    )
    docs, audit = pipeline.retrieve(corpus, ctx)
    print(f"  Permitted: {[d.document_id for d in docs]}")


if __name__ == "__main__":
    scenario_a_cleared_us_engineer()
    scenario_b_foreign_national()
    scenario_c_wrong_contract()
    scenario_d_foreign_with_license()
    print("\nAll scenarios complete.")
